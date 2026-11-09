#!/usr/bin/env bash
# Builds the published gray-assistant image (Dockerfile beside this file) from this checkout's HEAD and pushes it, tagged
# with the commit, to the repository the flags name, then signs it with cosign. Run it on the build box from a clean
# checkout of the commit to publish (scripts/ops/box-run.sh <commit> -- deploy/relay/image/release.sh ...). Prints the
# pushed digest last.
#
#   deploy/relay/image/release.sh --repository <registry>/<path> --username <user> --password-file <file>
#       --sign-key-file <file> [--sign-password-file <file>]
#       [--platforms linux/amd64,linux/arm64] [--source <url>] [--docker <docker command>] [--dry-run]
#
#   --repository      where to push, e.g. ghcr.io/<organisation>/gray-assistant (no default)
#   --username        the registry user the token belongs to
#   --password-file   a file holding the push token alone; read once into `docker login --password-stdin` under a
#                     throwaway DOCKER_CONFIG that is deleted afterwards. Never printed.
#   --platforms       default linux/amd64,linux/arm64 (arm64 runs the final stage's one RUN under QEMU)
#   --sign-key-file   Gray's relay release key: cosign's private key file (`cosign generate-key-pair`), a regular file
#                     of mode 0600, whose public half must be deploy/relay/kit/keys/gray-assistant-cosign.pub at the
#                     commit (checked before the build). Required to push. Copy it to the box for the release only.
#   --sign-password-file  the key's password alone in a 0600 file, read into COSIGN_PASSWORD only; none: empty
#   --source          the org.opencontainers.image.source label; none when not given
#   --docker          the docker command (the box's is ~/gray-tee/bin/docker); default $DOCKER, else docker
#   --dry-run         build for every platform without pushing, print what would be pushed
#
# The tag is the commit's first 12 characters. The image is built with GRAY_ASSISTANT_IMAGE=<repository>:<tag>, so
# `init --pair` in it writes a compose.yaml that runs exactly this tag; release notes should give the digest too
# (`<repository>:<tag>@sha256:...`) for operators who pin it. It is stamped with GRAY_ASSISTANT_VERSION=<kit version>+<tag>,
# the kit version being deploy/relay/kit/VERSION at the commit: what `gray-assistant --version` prints and the agent reports
# to Gray (the console's "gray-assistant <version>"), and the image's org.opencontainers.image.version.
#
# Signature and provenance. The build attaches BuildKit's SLSA provenance (mode=max: the Dockerfile, every build
# argument, the base images by digest) and an SPDX SBOM to the pushed index, and annotates the index with the commit
# and version; the index digest covers all of it. `deploy/relay/kit/cosign.sh sign-image` then signs that digest with
# --sign-key-file, the commit and version inside the signed payload, recorded in Sigstore's public transparency log,
# and `cosign.sh verify-image` checks it with the committed public key, as a relay does (deploy/relay/GUIDE.en.md
# section 2). cosign is the release cosign.sh pins, installed under GRAY_TOOLS_DIR on first use. BUILDX_GIT_INFO=0:
# the checkout's remote is a path on the box, which must not reach a public provenance; the labels and annotations
# carry the commit.
set -euo pipefail
umask 077
die() { echo "release.sh: $*" >&2; exit 2; }
repository="" username="" password_file="" sign_key_file="" sign_password_file="" platforms=linux/amd64,linux/arm64 source="" docker=${DOCKER:-docker} dry_run=0
while [ $# -gt 0 ]; do
  case $1 in
    --repository) repository=${2:?}; shift 2 ;;
    --username) username=${2:?}; shift 2 ;;
    --password-file) password_file=${2:?}; shift 2 ;;
    --sign-key-file) sign_key_file=${2:?}; shift 2 ;;
    --sign-password-file) sign_password_file=${2:?}; shift 2 ;;
    --platforms) platforms=${2:?}; shift 2 ;;
    --source) source=${2:?}; shift 2 ;;
    --docker) docker=${2:?}; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    -h | --help) awk 'NR > 1 && !/^#/ { exit } NR > 1' "$0"; exit 0 ;;
    *) die "unknown argument $1 (--help lists the flags)" ;;
  esac
done
[ -n "$repository" ] || die "--repository is required (e.g. ghcr.io/<organisation>/gray-assistant)"
[[ $repository =~ ^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+$ ]] || die "--repository must be <registry>/<path> in lower case, without a tag"
if [ "$dry_run" = 0 ]; then
  [ -n "$username" ] || die "--username is required"
  [ -n "$password_file" ] || die "--password-file is required"
  [ -f "$password_file" ] && [ ! -L "$password_file" ] || die "--password-file must be a regular file"
  [ -n "$sign_key_file" ] || die "--sign-key-file is required: a pushed release is signed with Gray's relay release key"
fi
secret_file() { # <flag> <file>: a regular file of mode 0600
  [ -f "$2" ] && [ ! -L "$2" ] || die "$1 must be a regular file"
  local mode
  mode=$(stat -c %a "$2" 2>/dev/null || stat -f %Lp "$2")
  [ "$mode" = 600 ] || die "$1 must have mode 0600 (it has $mode)"
}
if [ -n "$sign_key_file" ]; then secret_file --sign-key-file "$sign_key_file"; fi
if [ -n "$sign_password_file" ]; then
  secret_file --sign-password-file "$sign_password_file"
  COSIGN_PASSWORD=$(cat "$sign_password_file")
  export COSIGN_PASSWORD
fi
read -r -a dk <<<"$docker"
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
[ -z "$(git -C "$root" status --porcelain --untracked-files=no)" ] || die "the checkout has uncommitted changes; publish a commit"
sha=$(git -C "$root" rev-parse HEAD)
tag="${sha:0:12}"
image="$repository:$tag"
registry=${repository%%/*}

cosign_sh="$root/deploy/relay/kit/cosign.sh"
if ! git -C "$root" cat-file -e "$sha:deploy/relay/kit/keys/gray-assistant-cosign.pub" 2>/dev/null; then
  msg="deploy/relay/kit/keys/gray-assistant-cosign.pub is not in $tag: commit Gray's relay release public key first"
  [ "$dry_run" = 1 ] && [ -z "$sign_key_file" ] || die "$msg"
  echo "release.sh: $msg (a dry run goes on)" >&2
fi
# The key is checked now, not after a build of several minutes.
if [ -n "$sign_key_file" ]; then "$cosign_sh" check-key "$sign_key_file" || die "--sign-key-file is not Gray's relay release key"; fi

kit_version=$(git -C "$root" show "$sha:deploy/relay/kit/VERSION" 2>/dev/null | tr -d '[:space:]')
[[ $kit_version =~ ^[0-9A-Za-z][0-9A-Za-z.-]{0,40}$ ]] || die "deploy/relay/kit/VERSION at $tag holds no kit version"
version="$kit_version+$tag"

labels=(--label "org.opencontainers.image.revision=$sha" --label "org.opencontainers.image.version=$version"
  --annotation "index,manifest:org.opencontainers.image.revision=$sha"
  --annotation "index,manifest:org.opencontainers.image.version=$version")
if [ -n "$source" ]; then
  labels+=(--label "org.opencontainers.image.source=$source" --annotation "index,manifest:org.opencontainers.image.source=$source")
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/gray-assistant-release.XXXXXX")
# The login lives in this throwaway config only; it is logged out and deleted however the script ends. The build
# leaves the image in the local store under its own tag, removed at the end too.
export DOCKER_CONFIG="$work/docker"
mkdir -p "$DOCKER_CONFIG"
trap '"${dk[@]}" logout "$registry" >/dev/null 2>&1; "${dk[@]}" image rm "$image" >/dev/null 2>&1; rm -rf "$work" 2>/dev/null || true' EXIT
# cosign signs as this script's user with its own throwaway login: the build box's docker runs as root, so the
# config.json its login writes is root's alone and cosign could not read it (kit 1.0.8's first run, 2026-11-05).
cosign_config="$work/cosign"
mkdir -p "$cosign_config"
if [ "$dry_run" = 0 ]; then
  "${dk[@]}" login "$registry" --username "$username" --password-stdin <"$password_file" >/dev/null \
    || die "docker login to $registry failed"
  DOCKER_CONFIG="$cosign_config" "$("$cosign_sh" path)" login "$registry" --username "$username" --password-stdin \
    <"$password_file" >/dev/null 2>&1 || die "cosign login to $registry failed"
fi

echo "release.sh: building $image (gray-assistant $version) for $platforms"
push=false
if [ "$dry_run" = 0 ]; then push=true; fi
# Reproducible per platform (docs/design/public-source.md §7): every time in the image is the commit's (SOURCE_DATE_EPOCH:
# the config's and history's times and, through the RUN steps' environment, useradd's day in /etc/shadow;
# rewrite-timestamp: every file's time in the layers), so a rebuild from the published source has the same platform
# manifest digests. The provenance attestation keeps the build's own times, so the index digest differs. unpack=false:
# the docker driver on a containerd image store unpacks an image export by default, which BuildKit refuses beside
# rewrite-timestamp ("exporter option rewrite-timestamp conflicts with unpack"); the image is pushed, not run here.
source_date_epoch=$(git -C "$root" log -1 --format=%ct "$sha")
BUILDX_GIT_INFO=0 "${dk[@]}" buildx build --platform "$platforms" -f "$root/deploy/relay/image/Dockerfile" \
  --provenance=mode=max --sbom=true --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" --build-arg "GRAY_ASSISTANT_IMAGE=$image" \
  --build-arg "GRAY_ASSISTANT_VERSION=$version" "${labels[@]}" --output "type=image,name=$image,push=$push,rewrite-timestamp=true,unpack=false" "$root"
if [ "$dry_run" = 1 ]; then
  echo "release.sh: dry run, nothing pushed; would push $image"
  exit 0
fi
digest=$("${dk[@]}" buildx imagetools inspect "$image" --format '{{.Manifest.Digest}}')
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || die "pushed, but could not read the digest; read it with: docker buildx imagetools inspect $image"
echo "pushed $image"
DOCKER_CONFIG="$cosign_config" "$cosign_sh" sign-image "$sign_key_file" "$repository@$digest" "$sha" "$version" || die "pushed $image@$digest, but signing it failed"
DOCKER_CONFIG="$cosign_config" "$cosign_sh" verify-image "$repository@$digest" >&2 || die "signed $image@$digest, but the signature does not verify"
echo "signed $image@$digest"
echo "$image@$digest"
