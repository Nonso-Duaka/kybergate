// Bundles ML-KEM-768 from @noble/post-quantum into kybergate/web/static/vendor/mlkem.js
import { build } from "esbuild";
import { copyFileSync, readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync("node_modules/@noble/post-quantum/package.json", "utf8"));
const out = "../../kybergate/web/static/vendor";
await build({
  entryPoints: ["entry.js"],
  bundle: true,
  minify: true,
  format: "iife",
  globalName: "MLKEM",
  define: { NOBLE_VERSION: JSON.stringify(pkg.version) },
  banner: { js: `/*! @noble/post-quantum ${pkg.version} (ML-KEM-768 only) - MIT - (c) Paul Miller - https://github.com/paulmillr/noble-post-quantum */` },
  outfile: `${out}/mlkem.js`,
});
copyFileSync("node_modules/@noble/post-quantum/LICENSE", `${out}/LICENSE-noble-post-quantum`);
console.log(`built ${out}/mlkem.js from @noble/post-quantum ${pkg.version}`);
