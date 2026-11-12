# gray-assistant, the image published for relays (deploy/relay/GUIDE.en.md section 2): the CLI and the agent bundled into one
# module, the relay's page, frpc and Caddy, on a pinned Node. Nothing else of the repository is in it.
#
# Build from the repository root (release.sh does, for each platform):
#   docker build -f deploy/relay/image/Dockerfile --build-arg GRAY_ASSISTANT_IMAGE=<registry>/<repository>:<tag> \
#     --build-arg GRAY_ASSISTANT_VERSION=<kit version>+<commit, 12> -t <that> .
#
# - The bundle stage installs workers/ from its lockfile (`npm ci`) and bundles relay-kit's CLI with the esbuild the
#   lockfile pins (bundle.mjs). It runs on the build platform: the bundle is the same JavaScript for every platform.
# - The final stage gets only /opt/gray-assistant (bundle.mjs's header lists it): the bundle, the one dependency file it
#   loads at run time (dcap-qvl's collateral.js, bundled too), the npm licenses of the code in both, relay-kit's built
#   page and the policy interpreter (wasm) at the paths the bundle finds them by; and frpc and Caddy, each copied
#   from its project's image and pinned by its multi-arch index digest. No workspace source, no other
#   node_modules, no npm: the base image's npm and corepack are removed.
# - GRAY_ASSISTANT_IMAGE is the reference this image is pushed as. `gray-assistant init --pair` writes a compose.yaml that
#   runs it into the kit; empty (the default), `init --pair` writes no compose file.
# - The agent runs as uid/gid 10001 with every file root-owned and read-only; compose supplies the read-only root,
#   /tmp and the state volume.
ARG NODE_BASE=node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5
ARG FRPC_IMAGE=fatedier/frpc:v0.71.1@sha256:7a0a18bc9c83dc106a7e5213a890f521affdf90d595829c56b0ed8481377d50e
ARG CADDY_IMAGE=caddy:2.11.7-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f

FROM --platform=$BUILDPLATFORM ${NODE_BASE} AS bundle
# The version gray-assistant prints and reports: release.sh passes `<deploy/relay/kit/VERSION>+<commit, 12>`; empty, 0.0.0.
ARG GRAY_ASSISTANT_VERSION=""
WORKDIR /src
COPY workers ./workers
COPY deploy/relay/image/bundle.mjs ./bundle.mjs
RUN cd workers \
 && npm ci --ignore-scripts --no-audit --no-fund \
 && cd .. \
 && GRAY_ASSISTANT_VERSION="$GRAY_ASSISTANT_VERSION" node bundle.mjs workers /out

FROM ${FRPC_IMAGE} AS frpc

FROM ${CADDY_IMAGE} AS caddy
# The official image gives the binary cap_net_bind_service as a file capability, which the kernel refuses to execute
# with every capability dropped and no-new-privileges; a plain cp leaves the attribute behind.
RUN cp /usr/bin/caddy /caddy

FROM ${NODE_BASE}
ARG GRAY_ASSISTANT_IMAGE=""

LABEL org.opencontainers.image.title="gray-assistant" \
      org.opencontainers.image.description="Relay agent: attestation, sealed credentials, the signed scheduler, the relay tunnel and the operator CLI"

RUN groupadd --system --gid 10001 relay \
 && useradd --system --uid 10001 --gid 10001 --home-dir /var/lib/gray-assistant --shell /usr/sbin/nologin relay \
 && mkdir -p /etc/gray-assistant /var/lib/gray-assistant \
 && chown 10001:10001 /var/lib/gray-assistant \
 && rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg

COPY --from=bundle /out /opt/gray-assistant
COPY workers/packages/relay-kit/assets/ui /opt/gray-assistant/relay-kit/assets/ui
COPY workers/vendor/relay-policy-wasmi/relay_policy_wasmi.wasm workers/vendor/relay-policy-wasmi/LICENSE /opt/gray-assistant/vendor/relay-policy-wasmi/
COPY --from=frpc /usr/bin/frpc /usr/local/bin/frpc
COPY --from=caddy /caddy /usr/local/bin/caddy
# `gray-assistant` on the PATH, for `docker compose exec agent gray-assistant status` (exec does not use the entrypoint).
RUN chmod 0755 /opt/gray-assistant/relay-kit/dist/node/cli/gray-assistant.mjs \
 && ln -s /opt/gray-assistant/relay-kit/dist/node/cli/gray-assistant.mjs /usr/local/bin/gray-assistant

ENV NODE_ENV=production \
    GRAY_ASSISTANT_CONFIG=/etc/gray-assistant/gray-assistant.jsonc \
    GRAY_ASSISTANT_IMAGE=${GRAY_ASSISTANT_IMAGE}
USER 10001:10001
WORKDIR /var/lib/gray-assistant
STOPSIGNAL SIGTERM

ENTRYPOINT ["node", "/opt/gray-assistant/relay-kit/dist/node/cli/gray-assistant.mjs"]
CMD ["run", "--config", "/etc/gray-assistant/gray-assistant.jsonc"]
