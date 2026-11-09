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
#   --dry-run         build for every platform without pushing, print each platform's manifest digest and the index
#                     that would be pushed
#
# One build path with the published source's rebuild.sh (scripts/ops/public-source/templates/gray-assistant): the build
# context is `git archive` of the commit, built with --no-cache and exported as an OCI layout with rebuild.sh's
# exporter options; that layout is what is pushed (`docker buildx imagetools create` from oci-layout://), and the pushed
# index must have the layout's digest. Each platform's manifest digest is printed before the push, so a dry run and a
# rebuild can be compared (docs/design/public-source.md §7).
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
command -v node >/dev/null 2>&1 || die "node is required (it reads the OCI layout; box-run.sh puts the box's on the PATH)"
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
# The login lives in this throwaway config only; it is logged out and deleted however the script ends, with the build
# context and the OCI layout. Nothing is left in the local image store.
export DOCKER_CONFIG="$work/docker"
mkdir -p "$DOCKER_CONFIG"
# buildx keeps its state in $DOCKER_CONFIG/buildx unless BUILDX_CONFIG names another directory; where docker runs as
# root (the box) that directory is root's, and $work could not be removed (a directory was left in /tmp per release).
export BUILDX_CONFIG="${BUILDX_CONFIG:-$HOME/.docker/buildx}"
trap '"${dk[@]}" logout "$registry" >/dev/null 2>&1; rm -rf "$work" 2>/dev/null || true' EXIT
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
# Reproducible per platform (docs/design/public-source.md §7). Every time in the image is the commit's: SOURCE_DATE_EPOCH
# sets the config's and history's times and, through the RUN steps' environment, useradd's day in /etc/shadow;
# rewrite-timestamp sets every file time in the layers that is later than SOURCE_DATE_EPOCH. It leaves an earlier time
# as it is, and COPY keeps a context file's time. So the context is `git archive` of the commit, every file and
# directory dated the commit, not this checkout, whose files are dated whenever git last wrote them here: kit 1.3.0's
# first image carried those dates in two layers and did not rebuild to its digest (2026-11-10). A rebuild's tree is
# written after the commit, so rewrite-timestamp dates it the same. --no-cache: a layer from an earlier build would
# keep that build's times. The provenance attestation keeps the build's own times, so the index digest differs from a
# rebuild's; the platform manifests do not.
source_date_epoch=$(git -C "$root" log -1 --format=%ct "$sha")
context="$work/context"
mkdir -p "$context"
(umask 022 && git -C "$root" -c tar.umask=0022 archive "$sha" | tar -x -C "$context") || die "could not write $tag into the build context"
# The exporter options are rebuild.sh's. The layout comes through stdout (dest=-), so its files are this user's even
# where docker runs as root (the box), and leave with $work.
layout="$work/oci"
mkdir -p "$layout"
BUILDX_GIT_INFO=0 "${dk[@]}" buildx build --no-cache --platform "$platforms" -f "$context/deploy/relay/image/Dockerfile" \
  --provenance=mode=max --sbom=true --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" --build-arg "GRAY_ASSISTANT_IMAGE=$image" \
  --build-arg "GRAY_ASSISTANT_VERSION=$version" "${labels[@]}" --output "type=oci,dest=-,rewrite-timestamp=true" "$context" \
  | tar -x -C "$layout"
# The layout's image index (its blob checked against its digest), then each platform's manifest; attestations left out.
listing=$(node -e '
const fs = require("fs"), path = require("path"), crypto = require("crypto");
const dir = process.argv[1];
const top = JSON.parse(fs.readFileSync(path.join(dir, "index.json"), "utf8"));
if (top.manifests?.length !== 1 || top.manifests[0].mediaType !== "application/vnd.oci.image.index.v1+json") process.exit(1);
const digest = top.manifests[0].digest;
const blob = fs.readFileSync(path.join(dir, "blobs", ...digest.split(":")));
if (`sha256:${crypto.createHash("sha256").update(blob).digest("hex")}` !== digest) process.exit(1);
console.log(digest);
for (const m of JSON.parse(blob).manifests) {
  if (m.annotations?.["vnd.docker.reference.type"] === "attestation-manifest") continue;
  console.log(`${m.platform.os}/${m.platform.architecture}${m.platform.variant ? `/${m.platform.variant}` : ""} ${m.digest}`);
}' "$layout") || die "the build's OCI layout holds no image index"
index=${listing%%$'\n'*}
[[ $index =~ ^sha256:[0-9a-f]{64}$ ]] || die "the build's OCI layout holds no image index"
while read -r platform digest; do echo "release.sh: $platform manifest $digest"; done <<<"${listing#*$'\n'}"
echo "release.sh: index $index"
source_ref="oci-layout://$layout@$index"
if [ "$dry_run" = 1 ]; then
  # What the push would send: `imagetools create` copies a single index unchanged, so it prints the layout's index.
  "${dk[@]}" buildx imagetools create --dry-run --tag "$image" "$source_ref" >"$work/push.json" || die "imagetools create --dry-run failed"
  would=$(node -e 'const b = require("fs").readFileSync(0); const t = b[b.length - 1] === 10 ? b.subarray(0, -1) : b;
process.stdout.write(`sha256:${require("crypto").createHash("sha256").update(t).digest("hex")}`)' <"$work/push.json")
  [ "$would" = "$index" ] || die "imagetools create would push the index $would, not the layout's $index"
  echo "release.sh: dry run, nothing pushed; would push $image@$index"
  exit 0
fi
"${dk[@]}" buildx imagetools create --tag "$image" "$source_ref" >&2 || die "pushing the OCI layout to $image failed"
digest=$("${dk[@]}" buildx imagetools inspect "$image" --format '{{.Manifest.Digest}}')
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || die "pushed, but could not read the digest; read it with: docker buildx imagetools inspect $image"
[ "$digest" = "$index" ] || die "pushed $image, but the registry's index is $digest, not the built layout's $index; not signed"
echo "pushed $image"
DOCKER_CONFIG="$cosign_config" "$cosign_sh" sign-image "$sign_key_file" "$repository@$digest" "$sha" "$version" || die "pushed $image@$digest, but signing it failed"
DOCKER_CONFIG="$cosign_config" "$cosign_sh" verify-image "$repository@$digest" >&2 || die "signed $image@$digest, but the signature does not verify"
echo "signed $image@$digest"
echo "$image@$digest"
