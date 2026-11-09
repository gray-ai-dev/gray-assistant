// Bundles gray-assistant's CLI and everything it imports into one ES module with esbuild (the version workers/package-lock.json
// pins), and collects the license texts of the npm packages the bundle took code from. The image's build stage runs it
// (Dockerfile beside this file); nothing else of the workspace reaches the image.
//
//   node bundle.mjs <workers directory> <output directory>
//
// The output keeps the paths relay-kit finds its run-time files by, relative to the module (`import.meta.url`):
//   relay-kit/dist/node/cli/gray-assistant.mjs     the bundle
//   relay-kit/assets/ui/                       the relay's page, `../../../assets/ui/` (src/node/ui/server.ts); the
//                                              Dockerfile copies it
//   vendor/relay-policy-wasmi/                 the policy interpreter, `../../../../vendor/...` (src/node/interpreter.ts);
//                                              the Dockerfile copies it
//   node_modules/@phala/dcap-qvl/src/collateral.js
//                                              src/node/collateral-cache.ts loads it with createRequire, which no
//                                              bundler follows: that file and its imports, bundled as CommonJS
//   licenses/<package>/                        the license files of every npm package either bundle took code from
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, resolve, sep } from "node:path";

const [workersArg, outArg] = process.argv.slice(2);
if (workersArg === undefined || outArg === undefined) {
  console.error("usage: node bundle.mjs <workers directory> <output directory>");
  process.exit(2);
}
const workers = resolve(workersArg);
const out = resolve(outArg);
const require = createRequire(join(workers, "package.json"));
const esbuild = require("esbuild");

const BUNDLE = "relay-kit/dist/node/cli/gray-assistant.mjs";
const COLLATERAL = "node_modules/@phala/dcap-qvl/src/collateral.js";
// The version gray-assistant prints and reports (relay-kit src/endpoints.ts RELAY_KIT_VERSION): GRAY_ASSISTANT_VERSION, which
// release.sh sets to `<deploy/relay/kit/VERSION>+<commit, 12>`, in the form Gray's agent_version takes. Unset: 0.0.0.
const version = process.env.GRAY_ASSISTANT_VERSION ?? "";
if (version !== "" && !/^[0-9A-Za-z.+-]{1,64}$/.test(version)) {
  console.error("bundle.mjs: GRAY_ASSISTANT_VERSION must match [0-9A-Za-z.+-]{1,64}");
  process.exit(2);
}
const main = await esbuild.build({
  entryPoints: [join(workers, "packages/relay-kit/src/node/cli.ts")],
  outfile: join(out, BUNDLE),
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node24",
  define: version === "" ? {} : { __GRAY_ASSISTANT_VERSION__: JSON.stringify(version) },
  // CommonJS dependencies call require() for Node's built-ins, which an ES module has no binding for.
  banner: { js: 'import { createRequire as __createRequire } from "node:module"; const require = __createRequire(import.meta.url);' },
  // jsonc-parser's `main` is a UMD build whose require() calls esbuild cannot follow; its ES build (its `module`) is
  // the same code.
  plugins: [
    {
      name: "jsonc-parser-esm",
      setup(build) {
        const path = require.resolve("jsonc-parser/lib/esm/main.js");
        build.onResolve({ filter: /^jsonc-parser$/ }, () => ({ path }));
      },
    },
  ],
  legalComments: "none",
  metafile: true,
  logLevel: "warning",
});

const collateral = await esbuild.build({
  entryPoints: [require.resolve("@phala/dcap-qvl/src/collateral.js")],
  outfile: join(out, COLLATERAL),
  bundle: true,
  platform: "node",
  format: "cjs",
  target: "node24",
  legalComments: "none",
  metafile: true,
  logLevel: "warning",
});
// Its package.json, so the package resolves as on a checkout (no `exports`, CommonJS).
copyFileSync(require.resolve("@phala/dcap-qvl/package.json"), join(out, "node_modules/@phala/dcap-qvl/package.json"));

// One license directory per npm package a bundle took code from; the workspace's own packages have none to carry.
const packages = new Map();
// The metafile's paths are relative to the working directory, as esbuild's comments in the bundle are.
for (const input of [...Object.keys(main.metafile.inputs), ...Object.keys(collateral.metafile.inputs)]) {
  const path = resolve(input);
  const marker = `${sep}node_modules${sep}`;
  const at = path.lastIndexOf(marker);
  if (at < 0) continue;
  const rest = path.slice(at + marker.length).split(sep);
  const name = rest[0].startsWith("@") ? `${rest[0]}/${rest[1]}` : rest[0];
  packages.set(name, join(path.slice(0, at + marker.length), name));
}
const missing = [];
for (const [name, root] of [...packages].sort()) {
  const files = readdirSync(root).filter((file) => /^(licen[cs]e|copying|notice)/i.test(file));
  if (files.length === 0) {
    missing.push(name);
    continue;
  }
  const target = join(out, "licenses", name);
  mkdirSync(target, { recursive: true });
  for (const file of files) copyFileSync(join(root, file), join(target, file));
  const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  console.log(`bundled ${name}@${manifest.version} (${manifest.license ?? "no license field"})`);
}
// A package without a license file still has its package.json license field; keep that as the record.
for (const name of missing) {
  const root = packages.get(name);
  const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const target = join(out, "licenses", name);
  mkdirSync(target, { recursive: true });
  copyFileSync(join(root, "package.json"), join(target, "package.json"));
  console.log(`bundled ${name}@${manifest.version} (${manifest.license ?? "no license field"}; no license file, package.json kept)`);
}
for (const file of [BUNDLE, COLLATERAL]) if (!existsSync(join(out, file))) throw new Error(`esbuild wrote no ${file}`);
