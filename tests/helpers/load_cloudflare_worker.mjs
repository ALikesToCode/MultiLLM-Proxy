import { readFile } from "node:fs/promises";

function dataModuleUrl(source) {
  return `data:text/javascript;base64,${Buffer.from(source, "utf8").toString("base64")}`;
}

export async function roleplayModuleUrl() {
  const compatibilityUrl = new URL(
    "../../worker/roleplay/compatibility.mjs",
    import.meta.url,
  );
  const checkpointUrl = new URL(
    "../../worker/roleplay/checkpoint.mjs",
    import.meta.url,
  );
  const configUrl = new URL(
    "../../worker/roleplay/config.mjs",
    import.meta.url,
  );
  const directivesUrl = new URL(
    "../../worker/roleplay/directives.mjs",
    import.meta.url,
  );
  const fallbackMemoryUrl = new URL(
    "../../worker/roleplay/fallback-memory.mjs",
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
  const [
    compatibilitySource,
    checkpointSource,
    configSource,
    directivesSource,
    fallbackMemorySource,
    memorySource,
    transportSource,
    endpointSource,
  ] =
    await Promise.all([
      readFile(compatibilityUrl, "utf8"),
      readFile(checkpointUrl, "utf8"),
      readFile(configUrl, "utf8"),
      readFile(directivesUrl, "utf8"),
      readFile(fallbackMemoryUrl, "utf8"),
      readFile(memoryUrl, "utf8"),
      readFile(transportUrl, "utf8"),
      readFile(endpointUrl, "utf8"),
    ]);
  const compatibilityDataUrl = dataModuleUrl(compatibilitySource);
  const configDataUrl = dataModuleUrl(configSource);
  const directivesDataUrl = dataModuleUrl(directivesSource);
  const checkpointDataUrl = dataModuleUrl(
    checkpointSource.replace(
      'from "./directives.mjs";',
      `from "${directivesDataUrl}";`,
    ),
  );
  const fallbackMemoryDataUrl = dataModuleUrl(
    fallbackMemorySource.replace(
      'from "./directives.mjs";',
      `from "${directivesDataUrl}";`,
    ),
  );
  const memoryDataUrl = dataModuleUrl(
    memorySource.replace(
      'from "./directives.mjs";',
      `from "${directivesDataUrl}";`,
    ),
  );
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
    .replace(
      'from "./fallback-memory.mjs";',
      `from "${fallbackMemoryDataUrl}";`,
    )
    .replace(
      'from "./directives.mjs";',
      `from "${directivesDataUrl}";`,
    )
    .replace(
      'from "./compatibility.mjs";',
      `from "${compatibilityDataUrl}";`,
    )
    .replace(
      'from "./checkpoint.mjs";',
      `from "${checkpointDataUrl}";`,
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
