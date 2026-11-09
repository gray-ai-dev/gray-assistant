#!/usr/bin/env bash
# Checks that a gray-assistant image or a relay kit tarball is the one Gray published: Gray signs both with one cosign key
# (Sigstore cosign, key-based), whose public half is keys/gray-assistant-cosign.pub beside this script. Gray's release
# scripts sign with the same file (deploy/relay/image/release.sh, deploy/relay/kit/publish.sh).
#
#   cosign.sh verify <gray-assistant-kit-<version>.tar.gz>
#       the tarball against <tarball>.sigstore.json beside it, then the gray-assistant image its VERSIONS names (signed by
#       the same key, and built from the commit VERSIONS names). Prints what it checked.
#   cosign.sh verify-image <registry>/<path>[:<tag>][@sha256:<hex>]
#       one image, e.g. the `image:` line of your compose.yaml. Prints its digest, commit and version as signed.
#   cosign.sh path          installs the pinned cosign (below) if needed and prints its path
#   cosign.sh run <args>    runs the pinned cosign with <args>
#
#   --key <file>   verify with this public key instead of keys/gray-assistant-cosign.pub (option before the command)
#
# Gray's release scripts also use (never a relay):
#   cosign.sh sign-image <private key file> <registry>/<path>@sha256:<hex> <commit> <version>
#   cosign.sh sign-blob <private key file> <file>      writes <file>.sigstore.json
#   cosign.sh check-key <private key file>             fails unless its public half is the public key
# The private key is cosign's encrypted key file; its password is COSIGN_PASSWORD (empty when unset). The scripts refuse
# a private key whose public half is not keys/gray-assistant-cosign.pub.
#
# cosign: $COSIGN when set, else the pinned release below, downloaded once from sigstore/cosign's GitHub release into
# ${GRAY_TOOLS_DIR:-~/.cache/gray-tools}/cosign-<version>/ and checked against its sha256 before it runs (Linux and
# macOS, amd64 and arm64). Signing and verifying use Sigstore's public transparency log (Rekor): every signature Gray
# makes is recorded there, so a signature made with a leaked key cannot stay hidden. GRAY_COSIGN_OFFLINE=1 signs and
# verifies without it, for the scripts' own test against a local registry only.
set -euo pipefail
die() { echo "cosign.sh: $*" >&2; exit 2; }
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
KEY="$HERE/keys/gray-assistant-cosign.pub"

# The pin: cosign v3.1.4 (2026-10-20). Each sha256 is the release's cosign_checksums.txt line, which matches the
# digest GitHub lists for the asset.
COSIGN_VERSION=v3.1.4
cosign_sha256() {
  case $1 in
    linux-amd64) echo 424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa ;;
    linux-arm64) echo ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2 ;;
    darwin-amd64) echo 9d1e4abe2b6be279ed0d2ff706fde1ccd738747c834e3e6d44039c238867334f ;;
    darwin-arm64) echo 9f9b8cd557cf2e5b3df3373a00baa005a86b02391e3e06dd0ce37b3a1533d3a4 ;;
    *) return 1 ;;
  esac
}
sha256_of() { (command -v sha256sum >/dev/null && sha256sum "$1" || shasum -a 256 "$1") | cut -d' ' -f1; }

cosign_path() {
  if [ -n "${COSIGN:-}" ]; then echo "$COSIGN"; return; fi
  local os arch platform digest dir part
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case $(uname -m) in x86_64 | amd64) arch=amd64 ;; aarch64 | arm64) arch=arm64 ;; *) arch=$(uname -m) ;; esac
  platform="$os-$arch"
  digest=$(cosign_sha256 "$platform") || die "no pinned cosign for $platform; install cosign $COSIGN_VERSION yourself and set COSIGN=<its path>"
  dir="${GRAY_TOOLS_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/gray-tools}/cosign-$COSIGN_VERSION"
  if [ ! -x "$dir/cosign" ]; then
    mkdir -p "$(dirname "$dir")"
    part=$(mktemp -d "$dir.part.XXXXXX")
    echo "cosign.sh: downloading cosign $COSIGN_VERSION ($platform) into $dir" >&2
    if curl --fail --silent --show-error --location --retry 2 -o "$part/cosign" \
        "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-$platform" \
      && [ "$(sha256_of "$part/cosign")" = "$digest" ]; then
      chmod 0755 "$part/cosign"
      mv "$part" "$dir" 2>/dev/null || rm -rf "$part" # another install won the race: keep its copy
    else
      rm -rf "$part"
      die "the cosign $COSIGN_VERSION download failed or does not have the pinned sha256 $digest"
    fi
  fi
  echo "$dir/cosign"
}
cosign() { "$(cosign_path)" "$@"; }

offline=()
offline_verify=()
if [ "${GRAY_COSIGN_OFFLINE:-}" = 1 ]; then
  echo "cosign.sh: GRAY_COSIGN_OFFLINE=1: no transparency log (the scripts' own test only)" >&2
  offline=(--use-signing-config=false --tlog-upload=false)
  offline_verify=(--insecure-ignore-tlog=true)
fi

need_key() {
  [ -f "$KEY" ] || die "no public key at $KEY: Gray's signing key is not in this checkout or kit (deploy/relay/kit/keys/gray-assistant-cosign.pub)"
}
signer() { echo "sha256:$(sha256_of "$KEY") ($KEY)"; }
# The private key's public half must be the committed key: a release is never signed with another.
check_private_key() {
  local private=$1 public
  need_key
  [ -f "$private" ] && [ ! -L "$private" ] || die "the signing key must be a regular file: $private"
  public=$(COSIGN_PASSWORD=${COSIGN_PASSWORD:-} cosign public-key --key "$private" 2>/dev/null) \
    || die "cosign cannot read the signing key $private (wrong password? set COSIGN_PASSWORD)"
  [ "$public" = "$(cat "$KEY")" ] || die "the signing key's public half is not $KEY; sign with Gray's relay release key"
}

verify_image() { # <ref> -> prints image, digest, commit, version
  local ref=$1 digest payload out
  need_key
  out=$(mktemp)
  # `cosign verify` resolves a tag to its digest; the printed payload names the digest that was signed.
  if ! cosign verify --key "$KEY" ${offline_verify[@]+"${offline_verify[@]}"} --output json "$ref" >"$out" 2>"$out.err"; then
    cat "$out.err" >&2
    rm -f "$out" "$out.err"
    die "$ref: no valid signature by $KEY"
  fi
  payload=$(cat "$out")
  rm -f "$out" "$out.err"
  python3 -I -c '
import json, sys
items = json.loads(sys.argv[1])
digests = {i["critical"]["image"]["docker-manifest-digest"] for i in items}
optional = [i.get("optional") or {} for i in items]
commits = {o.get("org.opencontainers.image.revision") for o in optional} - {None}
versions = {o.get("org.opencontainers.image.version") for o in optional} - {None}
if len(digests) != 1 or len(commits) != 1:
    sys.exit("cosign.sh: the signatures name %d digests and %d commits; expected one of each" % (len(digests), len(commits)))
print(digests.pop(), commits.pop(), (versions.pop() if len(versions) == 1 else "-"))
' "$payload"
}

cmd_verify_image() {
  local ref=${1:?verify-image needs an image reference} digest commit version
  read -r digest commit version < <(verify_image "$ref")
  echo "image    ${ref%@*}@$digest"
  echo "commit   $commit"
  echo "version  $version"
  echo "signer   $(signer)"
  echo "cosign.sh: OK: the image is signed by Gray's relay release key"
}

cmd_verify() {
  local tarball=${1:?verify needs the kit tarball} bundle versions image commit digest signed_commit version
  [ -f "$tarball" ] || die "no file $tarball"
  bundle="$tarball.sigstore.json"
  [ -f "$bundle" ] || die "no signature $bundle: download it from beside the tarball"
  need_key
  cosign verify-blob --key "$KEY" --bundle "$bundle" ${offline_verify[@]+"${offline_verify[@]}"} "$tarball" >/dev/null 2>"$bundle.err" \
    || { cat "$bundle.err" >&2; rm -f "$bundle.err"; die "$tarball: the signature does not verify with $KEY"; }
  rm -f "$bundle.err"
  echo "kit      $tarball"
  echo "sha256   $(sha256_of "$tarball")"
  echo "signer   $(signer)"
  versions=$(tar -xzOf "$tarball" gray-assistant-kit/VERSIONS) || die "$tarball has no gray-assistant-kit/VERSIONS"
  image=$(sed -n 's/^gray_assistant_image=//p' <<<"$versions")
  commit=$(sed -n 's/^gray_assistant_commit=//p' <<<"$versions")
  [[ $image =~ @sha256:[0-9a-f]{64}$ ]] || die "the kit's VERSIONS names no released gray-assistant image ($image)"
  read -r digest signed_commit version < <(verify_image "$image")
  [ "$digest" = "${image##*@}" ] || die "$image: the signature covers $digest"
  [ -z "$commit" ] || [ "$signed_commit" = "$commit" ] \
    || die "$image is signed as built from $signed_commit, but the kit's VERSIONS says $commit"
  echo "image    $image"
  echo "commit   $signed_commit"
  echo "version  $version"
  echo "cosign.sh: OK: the kit and its gray-assistant image are signed by Gray's relay release key"
}

cmd_sign_image() {
  local private=${1:?} ref=${2:?} commit=${3:?} version=${4:?}
  [[ $ref =~ @sha256:[0-9a-f]{64}$ ]] || die "sign-image takes the image by digest"
  check_private_key "$private"
  COSIGN_PASSWORD=${COSIGN_PASSWORD:-} cosign sign --yes --key "$private" ${offline[@]+"${offline[@]}"} \
    -a "org.opencontainers.image.revision=$commit" -a "org.opencontainers.image.version=$version" "$ref" >&2
}

cmd_sign_blob() {
  local private=${1:?} file=${2:?}
  [ -f "$file" ] || die "no file $file"
  check_private_key "$private"
  COSIGN_PASSWORD=${COSIGN_PASSWORD:-} cosign sign-blob --yes --key "$private" ${offline[@]+"${offline[@]}"} \
    --bundle "$file.sigstore.json" "$file" >/dev/null
  echo "$file.sigstore.json"
}

if [ "${1:-}" = --key ]; then KEY=${2:?--key needs a file}; shift 2; fi
case ${1:-} in
  verify) shift; cmd_verify "$@" ;;
  verify-image) shift; cmd_verify_image "$@" ;;
  sign-image) shift; cmd_sign_image "$@" ;;
  sign-blob) shift; cmd_sign_blob "$@" ;;
  check-key) shift; check_private_key "${1:?check-key needs the private key file}" ;;
  path) cosign_path ;;
  run) shift; cosign "$@" ;;
  -h | --help | "") awk 'NR > 1 && !/^#/ { exit } NR > 1' "$0" ;;
  *) die "unknown command $1 (--help lists them)" ;;
esac
