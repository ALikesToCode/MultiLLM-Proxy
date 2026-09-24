import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import postcss from "postcss";

const root = fileURLToPath(new URL("..", import.meta.url));
const require = createRequire(import.meta.url);
const cliManifest = require.resolve("@tailwindcss/cli/package.json");
const cli = join(dirname(cliManifest), JSON.parse(readFileSync(cliManifest)).bin.tailwindcss);

function buildFixture(t) {
  const directory = mkdtempSync(join(tmpdir(), "multillm-css-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const path of ["templates", "static/css", "static/js"]) {
    mkdirSync(join(directory, path), { recursive: true });
  }
  symlinkSync(realpathSync(join(root, "node_modules")), join(directory, "node_modules"), "junction");
  for (const path of ["tailwind.config.js", "static/css/main.css"]) {
    copyFileSync(join(root, path), join(directory, path));
  }
  writeFileSync(join(directory, "templates/page.html"), '<div class="bg-fuchsia-700 hidden"></div>');
  writeFileSync(join(directory, "static/js/page.js"), 'element.className = "p-11";');
  writeFileSync(join(directory, "static/js/module.mjs"), 'element.className = "md:grid-cols-7";');
  writeFileSync(join(directory, "notes.html"), '<div class="bg-lime-900"></div>');
  return directory;
}

function assertStyles(css) {
  const sheet = postcss.parse(css);
  const selectors = new Map();
  sheet.walkRules(rule => selectors.set(rule.selector, rule));
  for (const selector of [".bg-fuchsia-700", ".p-11", ".md\\:grid-cols-7"]) {
    assert.ok(selectors.has(selector), `Missing template or script class: ${selector}`);
  }
  assert.ok(!selectors.has(".bg-lime-900"), "Files outside configured sources must not be scanned");
  const hidden = [];
  sheet.walkRules(".hidden", rule => rule.walkDecls("display", declaration => hidden.push(declaration)));
  assert.ok(hidden.some(declaration => declaration.value === "none" && declaration.important),
    "Hide/show controls must override component display styles");
  sheet.walkAtRules(rule => {
    assert.notEqual(rule.name, "tailwind", "Tailwind directives must be compiled");
    assert.ok(rule.name !== "import" || !rule.params.includes("tailwindcss"), "Tailwind imports must be bundled");
  });
}

test("Tailwind CLI compiles configured template and script sources", t => {
  const directory = buildFixture(t);
  const output = join(directory, "output.css");
  execFileSync(process.execPath, [cli, "-i", "static/css/main.css", "-o", output], {
    cwd: directory,
    stdio: "pipe",
  });
  assertStyles(readFileSync(output, "utf8"));
});

test("PostCSS configuration compiles the same frontend styles", async t => {
  const directory = buildFixture(t);
  const config = require("../postcss.config.js");
  const plugins = Object.entries(config.plugins).map(([name, options]) => require(name)(options));
  const input = join(directory, "static/css/main.css");
  const result = await postcss(plugins).process(readFileSync(input, "utf8"), { from: input });
  assertStyles(result.css);
});
