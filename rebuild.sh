#!/usr/bin/env bash
# Rebuilds the gray-assistant image of v1.6.0-c2e520675725 for one platform from this tree, with the build command of
# deploy/relay/image/release.sh (the script Gray publishes with): the same Dockerfile, build arguments, labels and
# annotations, and prints the platform's OCI manifest digest. Compare it with the published image's manifest for the
# same platform (README.md, "Rebuild"):
#
#   ./rebuild.sh                              # linux/amd64
#   PLATFORM=linux/arm64 ./rebuild.sh
#   docker buildx imagetools inspect ghcr.io/gray-ai-dev/gray-assistant:c2e520675725     # the published digests, per platform
#
# The build fixes every time in the image to the commit's (SOURCE_DATE_EPOCH, rewrite-timestamp), as
# deploy/relay/image/release.sh does when it passes SOURCE_DATE_EPOCH. rewrite-timestamp sets only the times later
# than the commit, which every file of this tree has (it was written after the commit); release.sh builds from
# `git archive` of the commit, whose files carry the commit's time, and exports its OCI layout with the options below.
# An image an earlier release.sh built (kit 1.1.1 and before) differs in its times alone; README.md, "What is not
# reproducible yet", says how its files are compared.
#
# Needs docker with buildx and a builder that can export an OCI layout. Network: Docker Hub (three pinned images) and
# npm's registry (the bundle stage runs npm ci from workers/package-lock.json).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
commit=c2e520675725c8c771b79e1a42383f2a47265a7f
epoch=1794587846
platform=${PLATFORM:-linux/amd64}
image=ghcr.io/gray-ai-dev/gray-assistant:c2e520675725
version=1.6.0+c2e520675725
out="$here/rebuild"
command -v docker >/dev/null 2>&1 || { echo "rebuild.sh: docker is required" >&2; exit 2; }
rm -rf "$out" && mkdir -p "$out"
echo "rebuild.sh: building $image (gray-assistant $version) for $platform"
# --no-cache: a build that reuses an earlier build's layers would also reuse their file times, and match for that reason.
BUILDX_GIT_INFO=0 docker buildx build --no-cache --platform "$platform" -f "$here/deploy/relay/image/Dockerfile" \
  --provenance=false --build-arg "SOURCE_DATE_EPOCH=$epoch" --build-arg "GRAY_ASSISTANT_IMAGE=$image" --build-arg "GRAY_ASSISTANT_VERSION=$version" \
  --label "org.opencontainers.image.revision=$commit" --label "org.opencontainers.image.version=$version" \
  --annotation "manifest:org.opencontainers.image.revision=$commit" \
  --annotation "manifest:org.opencontainers.image.version=$version" \
  --output "type=oci,dest=$out/image.tar,rewrite-timestamp=true" "$here" >"$out/build.log" 2>&1 || { tail -n 30 "$out/build.log" >&2; exit 1; }
digest=$(tar -xOf "$out/image.tar" index.json | node -e 'let s="";process.stdin.on("data",(d)=>{s+=d}).on("end",()=>{const i=JSON.parse(s);if(i.manifests.length!==1){process.exit(1)}process.stdout.write(i.manifests[0].digest)})')
echo "rebuild.sh: commit $commit"
echo "rebuild.sh: oci $out/image.tar"
echo "rebuild.sh: manifest $digest"
