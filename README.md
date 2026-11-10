# gray-assistant v1.3.6 (v1.3.6-fdf7584ba813)

The source of `gray-assistant` 1.3.6, built from Gray's commit `fdf7584ba81319d16f428b9ee28176dfed41fc71`. gray-assistant is the agent a relay runs
on its own server, and it holds the relay's account credentials. It checks a lane CVM's attestation and Gray's signed
release list. It seals each credential to a boot it has verified. It accepts Gray's releases. It also serves the
relay's page, where the relay enters its keys.

This tree holds exactly the 484 files that the published image `ghcr.io/gray-ai-dev/gray-assistant:fdf7584ba813` and the
relay's page are built from, at the paths they have in Gray's repository. Tests, documentation and Gray's other
services are not included. Each release is one commit in this repository, and its parent is the release published
before it, so `git diff <previous tag> v1.3.6-fdf7584ba813` shows the code that changed between the two.

| Part | Where its source is |
|-|-|
| the CLI and the agent, bundled into one module | `workers/packages/relay-kit/src/`, and the `workers/packages/` it imports; entry `workers/packages/relay-kit/src/node/cli.ts` |
| attestation and release checks | `workers/packages/relay-kit/src/verified-report.ts`, `workers/packages/relay-kit/src/node/attest.ts`, `workers/packages/relay-kit/src/daemon/releases.ts`, `workers/packages/lane-verify/` |
| sealing credentials to a verified boot | `workers/packages/relay-kit/src/seal.ts`, `workers/packages/relay-connector/` |
| the relay's page: its source, and the server that serves it | `frontend/src/relay-ui/`, the console's design system under `frontend/src/`, built by `frontend/relay-ui/vite.config.ts`; served by `workers/packages/relay-kit/src/node/ui/` |
| the relay's page as the image carries it (built, committed) | `workers/packages/relay-kit/assets/ui/` |
| the image | `deploy/relay/image/Dockerfile`, `deploy/relay/image/bundle.mjs`, built and signed by `deploy/relay/image/release.sh` |

## From a version to this tag

The image's tag is the first 12 hex digits of the commit (`ghcr.io/gray-ai-dev/gray-assistant:fdf7584ba813`), and its version
label is `1.3.6+fdf7584ba813`. This repository's tag is `v<kit version>-<the same 12 hex digits>`.
`deploy/relay/kit/cosign.sh verify-image <image>` checks Gray's signature on an image with the key in
`deploy/relay/kit/keys/gray-assistant-cosign.pub`. The signed payload names the commit.

## What to review

> Review this tree (and `git diff <the tag you run now> v1.3.6-fdf7584ba813`) for any way gray-assistant could retain or transmit
> the relay's account keys other than sealed to a CVM boot it has verified. Trace: (1) where credentials enter: the
> relay's page (`frontend/src/relay-ui/`) and the server behind it (`workers/packages/relay-kit/src/node/ui/`), the
> configuration and its sources, and the logins and token refreshes (`workers/packages/relay-kit/src/node/source/`,
> `workers/packages/relay-kit/src/node/login/`); (2) every network path out: each `fetch`, socket and the host it can
> reach, in the agent and in the page, and the tunnel (`workers/packages/relay-kit/src/node/tunnel/`); (3) the checks
> that must pass before anything is sealed: attestation, the release list and its signature, and acceptance;
> (4) storage: what the state volume and the browser keep, and in what form. Report each place a credential, or a
> value derived from it, is logged, stored unsealed, or sent anywhere other than its vendor or sealed to a verified
> boot.

## Rebuild

`./rebuild.sh` builds the image for one platform (linux/amd64 by default, `PLATFORM=linux/arm64` for the other)
with the build command of `deploy/relay/image/release.sh`. It prints `rebuild.sh: manifest sha256:…`. Compare that
digest with the published image's manifest for the same platform: `docker buildx imagetools inspect --raw ghcr.io/gray-ai-dev/gray-assistant:fdf7584ba813`
lists one manifest per platform.

The page: run `npm ci` and then `RELAY_UI_OUT=<an empty directory> npx vite build --config relay-ui/vite.config.ts`
in `frontend/`. The result is `workers/packages/relay-kit/assets/ui/`, file for file. Gray builds it this way from
this tree before it publishes a tag, and refuses to publish when the two differ.

## What is not reproducible yet

- Nothing in the image itself: each platform's manifest digest is reproducible (`./rebuild.sh`).
- frpc and Caddy are copied unchanged from their projects' images, which `deploy/relay/image/Dockerfile` pins by
  digest.
- The image index's digest: Gray attaches a provenance attestation with the build's own times. Compare the
  manifest of each platform, not the index.

## License

No license is granted. The source is published so that it can be reviewed and rebuilt. All rights are reserved by
Gray. Third-party code bundled into the image keeps its own license, and the image carries those licenses under
`/opt/gray-assistant/licenses/`.
