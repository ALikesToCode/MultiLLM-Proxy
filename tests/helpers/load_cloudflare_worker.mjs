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
  const capacityUrl = new URL(
    "../../worker/roleplay/capacity.mjs",
    import.meta.url,
  );
  const configUrl = new URL(
    "../../worker/roleplay/config.mjs",
    import.meta.url,
  );
  const credentialHealthUrl = new URL(
    "../../worker/roleplay/credential-health.mjs",
    import.meta.url,
  );
  const compactionPolicyUrl = new URL(
    "../../worker/roleplay/compaction-policy.mjs",
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
  const messageFragmentsUrl = new URL(
    "../../worker/roleplay/message-fragments.mjs",
    import.meta.url,
  );
  const outputContractUrl = new URL(
    "../../worker/roleplay/output-contract.mjs",
    import.meta.url,
  );
  const outputBudgetUrl = new URL(
    "../../worker/roleplay/output-budget.mjs",
    import.meta.url,
  );
  const continuationUrl = new URL(
    "../../worker/roleplay/continuation.mjs",
    import.meta.url,
  );
  const promptCacheUrl = new URL(
    "../../worker/roleplay/prompt-cache.mjs",
    import.meta.url,
  );
  const reasoningUrl = new URL(
    "../../worker/roleplay/reasoning.mjs",
    import.meta.url,
  );
  const sessionStorageUrl = new URL(
    "../../worker/roleplay/session-storage.mjs",
    import.meta.url,
  );
  const validationUrl = new URL(
    "../../worker/roleplay/validation.mjs",
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
  const streamingUrl = new URL(
    "../../worker/roleplay/streaming.mjs",
    import.meta.url,
  );
  const reasoningOutputUrl = new URL(
    "../../worker/roleplay/reasoning-output.mjs",
    import.meta.url,
  );
  const [
    compatibilitySource,
    checkpointSource,
    capacitySource,
    configSource,
    credentialHealthSource,
    compactionPolicySource,
    directivesSource,
    fallbackMemorySource,
    memorySource,
    messageFragmentsSource,
    outputContractSource,
    outputBudgetSource,
    continuationSource,
    promptCacheSource,
    reasoningSource,
    sessionStorageSource,
    validationSource,
    transportSource,
    reasoningOutputSource,
    streamingSource,
    endpointSource,
  ] =
    await Promise.all([
      readFile(compatibilityUrl, "utf8"),
      readFile(checkpointUrl, "utf8"),
      readFile(capacityUrl, "utf8"),
      readFile(configUrl, "utf8"),
      readFile(credentialHealthUrl, "utf8"),
      readFile(compactionPolicyUrl, "utf8"),
      readFile(directivesUrl, "utf8"),
      readFile(fallbackMemoryUrl, "utf8"),
      readFile(memoryUrl, "utf8"),
      readFile(messageFragmentsUrl, "utf8"),
      readFile(outputContractUrl, "utf8"),
      readFile(outputBudgetUrl, "utf8"),
      readFile(continuationUrl, "utf8"),
      readFile(promptCacheUrl, "utf8"),
      readFile(reasoningUrl, "utf8"),
      readFile(sessionStorageUrl, "utf8"),
      readFile(validationUrl, "utf8"),
      readFile(transportUrl, "utf8"),
      readFile(reasoningOutputUrl, "utf8"),
      readFile(streamingUrl, "utf8"),
      readFile(endpointUrl, "utf8"),
    ]);
  const compatibilityDataUrl = dataModuleUrl(compatibilitySource);
  const capacityDataUrl = dataModuleUrl(capacitySource);
  const configDataUrl = dataModuleUrl(
    configSource.replace(
      'from "./capacity.mjs";',
      `from "${capacityDataUrl}";`,
    ),
  );
  const credentialHealthDataUrl = dataModuleUrl(
    credentialHealthSource.replace(
      'from "./config.mjs";',
      `from "${configDataUrl}";`,
    ),
  );
  const compactionPolicyDataUrl = dataModuleUrl(
    compactionPolicySource,
  );
  const reasoningOutputDataUrl = dataModuleUrl(reasoningOutputSource);
  const streamingDataUrl = dataModuleUrl(
    streamingSource.replace(
      'from "./reasoning-output.mjs";',
      `from "${reasoningOutputDataUrl}";`,
    ),
  );
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
  const outputContractDataUrl = dataModuleUrl(outputContractSource);
  const validationDataUrl = dataModuleUrl(validationSource);
  const outputBudgetDataUrl = dataModuleUrl(
    outputBudgetSource.replace(
      'from "./validation.mjs";',
      `from "${validationDataUrl}";`,
    ),
  );
  const promptCacheDataUrl = dataModuleUrl(promptCacheSource);
  const reasoningDataUrl = dataModuleUrl(reasoningSource);
  const messageFragmentsDataUrl = dataModuleUrl(messageFragmentsSource);
  const sessionStorageDataUrl = dataModuleUrl(
    sessionStorageSource.replace(
      'from "./message-fragments.mjs";',
      `from "${messageFragmentsDataUrl}";`,
    ),
  );
  const memoryDataUrl = dataModuleUrl(
    memorySource
      .replace(
        'from "./directives.mjs";',
        `from "${directivesDataUrl}";`,
      )
      .replace(
        'from "./output-contract.mjs";',
        `from "${outputContractDataUrl}";`,
      )
      .replace(
        'from "./output-budget.mjs";',
        `from "${outputBudgetDataUrl}";`,
      )
      .replace(
        'from "./reasoning.mjs";',
        `from "${reasoningDataUrl}";`,
      )
      .replaceAll(
        'from "./validation.mjs";',
        `from "${validationDataUrl}";`,
      ),
  );
  const transportDataUrl = dataModuleUrl(
    transportSource
      .replace(
        'from "./capacity.mjs";',
        `from "${capacityDataUrl}";`,
      )
      .replace('from "./config.mjs";', `from "${configDataUrl}";`)
      .replace('from "./memory.mjs";', `from "${memoryDataUrl}";`)
      .replace(
        'from "./message-fragments.mjs";',
        `from "${messageFragmentsDataUrl}";`,
      ),
  );
  const continuationDataUrl = dataModuleUrl(
    continuationSource
      .replace(
        'from "./capacity.mjs";',
        `from "${capacityDataUrl}";`,
      )
      .replace('from "./memory.mjs";', `from "${memoryDataUrl}";`)
      .replace(
        'from "./prompt-cache.mjs";',
        `from "${promptCacheDataUrl}";`,
      )
      .replace(
        'from "./output-contract.mjs";',
        `from "${outputContractDataUrl}";`,
      )
      .replace(
        'from "./transport.mjs";',
        `from "${transportDataUrl}";`,
      ),
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
      'from "./continuation.mjs";',
      `from "${continuationDataUrl}";`,
    )
    .replace(
      'from "./directives.mjs";',
      `from "${directivesDataUrl}";`,
    )
    .replace(
      'from "./credential-health.mjs";',
      `from "${credentialHealthDataUrl}";`,
    )
    .replace(
      'from "./compatibility.mjs";',
      `from "${compatibilityDataUrl}";`,
    )
    .replace(
      'from "./checkpoint.mjs";',
      `from "${checkpointDataUrl}";`,
    )
    .replace(
      'from "./compaction-policy.mjs";',
      `from "${compactionPolicyDataUrl}";`,
    )
    .replace(
      'from "./capacity.mjs";',
      `from "${capacityDataUrl}";`,
    )
    .replace('from "./config.mjs";', `from "${configDataUrl}";`)
    .replace('from "./memory.mjs";', `from "${memoryDataUrl}";`)
    .replace(
      'from "./output-contract.mjs";',
      `from "${outputContractDataUrl}";`,
    )
    .replace(
      'from "./prompt-cache.mjs";',
      `from "${promptCacheDataUrl}";`,
    )
    .replace(
      'from "./reasoning-output.mjs";',
      `from "${reasoningOutputDataUrl}";`,
    )
    .replace(
      'from "./session-storage.mjs";',
      `from "${sessionStorageDataUrl}";`,
    )
    .replace('from "./transport.mjs";', `from "${transportDataUrl}";`)
    .replace('from "./streaming.mjs";', `from "${streamingDataUrl}";`);
  return dataModuleUrl(patchedEndpoint);
}

export async function loadRoleplayModule() {
  return import(await roleplayModuleUrl());
}

export async function loadRoleplayStreamingModule() {
  const streamingUrl = new URL(
    "../../worker/roleplay/streaming.mjs",
    import.meta.url,
  );
  const reasoningOutputUrl = new URL(
    "../../worker/roleplay/reasoning-output.mjs",
    import.meta.url,
  );
  const [streamingSource, reasoningOutputSource] = await Promise.all([
    readFile(streamingUrl, "utf8"),
    readFile(reasoningOutputUrl, "utf8"),
  ]);
  return import(
    dataModuleUrl(
      streamingSource.replace(
        'from "./reasoning-output.mjs";',
        `from "${dataModuleUrl(reasoningOutputSource)}";`,
      ),
    )
  );
}

export async function loadWorkerModule() {
  const workerUrl = new URL("../../cloudflare-worker.mjs", import.meta.url);
  const opencodeReasoningUrl = new URL(
    "../../worker/opencode/reasoning-response.mjs",
    import.meta.url,
  );
  const reasoningOutputUrl = new URL(
    "../../worker/roleplay/reasoning-output.mjs",
    import.meta.url,
  );
  const [source, opencodeReasoningSource, reasoningOutputSource] =
    await Promise.all([
      readFile(workerUrl, "utf8"),
      readFile(opencodeReasoningUrl, "utf8"),
      readFile(reasoningOutputUrl, "utf8"),
    ]);
  const endpointDataUrl = await roleplayModuleUrl();
  const opencodeReasoningDataUrl = dataModuleUrl(
    opencodeReasoningSource.replace(
      'from "../roleplay/reasoning-output.mjs";',
      `from "${dataModuleUrl(reasoningOutputSource)}";`,
    ),
  );
  const patchedSource = source
    .replace(
      /import\s+\{[^}]+\}\s+from\s+"@cloudflare\/containers";/,
      "class Container {}\nconst getContainer = (binding, name) => binding.getByName(name);\nconst switchPort = (request) => request;",
    )
    .replace(
      'from "./worker/roleplay/endpoint.mjs";',
      `from "${endpointDataUrl}";`,
    )
    .replace(
      'from "./worker/opencode/reasoning-response.mjs";',
      `from "${opencodeReasoningDataUrl}";`,
    );

  return import(dataModuleUrl(patchedSource));
}
