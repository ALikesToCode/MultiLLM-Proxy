import { readFile } from "node:fs/promises";

function dataModuleUrl(source) {
  return `data:text/javascript;base64,${Buffer.from(source, "utf8").toString("base64")}`;
}

export async function roleplayModuleUrl() {
  const configUrl = new URL(
    "../../worker/roleplay/config.mjs",
    import.meta.url,
  );
  const memoryUrl = new URL(
    "../../worker/roleplay/memory.mjs",
    import.meta.url,
  );
  const endpointUrl = new URL(
    "../../worker/roleplay/endpoint.mjs",
    import.meta.url,
  );
  const transportUrl = new URL(
    "../../worker/roleplay/transport.mjs",
    import.meta.url,
  );
  const [configSource, memorySource, transportSource, endpointSource] =
    await Promise.all([
      readFile(configUrl, "utf8"),
      readFile(memoryUrl, "utf8"),
      readFile(transportUrl, "utf8"),
      readFile(endpointUrl, "utf8"),
    ]);
  const configDataUrl = dataModuleUrl(configSource);
  const memoryDataUrl = dataModuleUrl(memorySource);
  const transportDataUrl = dataModuleUrl(
    transportSource
      .replace('from "./config.mjs";', `from "${configDataUrl}";`)
      .replace('from "./memory.mjs";', `from "${memoryDataUrl}";`),
  );
  const patchedEndpoint = endpointSource
    .replace(
      'import { DurableObject } from "cloudflare:workers";',
      "class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }",
    )
    .replace('from "./config.mjs";', `from "${configDataUrl}";`)
    .replace('from "./memory.mjs";', `from "${memoryDataUrl}";`)
    .replace('from "./transport.mjs";', `from "${transportDataUrl}";`);
  return dataModuleUrl(patchedEndpoint);
}

export async function loadRoleplayModule() {
  return import(await roleplayModuleUrl());
}

export async function loadWorkerModule() {
  const workerUrl = new URL("../../cloudflare-worker.mjs", import.meta.url);
  const source = await readFile(workerUrl, "utf8");
  const endpointDataUrl = await roleplayModuleUrl();
  const patchedSource = source
    .replace(
      /import\s+\{[^}]+\}\s+from\s+"@cloudflare\/containers";/,
      "class Container {}\nconst getContainer = (binding, name) => binding.getByName(name);\nconst switchPort = (request) => request;",
    )
    .replace(
      'from "./worker/roleplay/endpoint.mjs";',
      `from "${endpointDataUrl}";`,
    );

  return import(dataModuleUrl(patchedSource));
}
