import { loadRoleplayModule } from "./load_cloudflare_worker.mjs";

const {
  RoleplaySession,
  handleRoleplayEdgeRequest,
} = await loadRoleplayModule();

class FakeStorage {
  constructor() {
    this.values = new Map();
    this.alarm = null;
  }

  async get(key) {
    return structuredClone(this.values.get(key));
  }

  async put(key, value) {
    if (key && typeof key === "object" && !Array.isArray(key)) {
      for (const [entryKey, entryValue] of Object.entries(key)) {
        this.values.set(entryKey, structuredClone(entryValue));
      }
      return;
    }
    this.values.set(key, structuredClone(value));
  }

  async setAlarm(value) {
    this.alarm = value;
  }

  async deleteAll() {
    this.values.clear();
    this.alarm = null;
  }
}

export function makeRoleplayEnv(overrides = {}) {
  const storageBySession = new Map();
  const waits = [];
  const env = {
    ADMIN_API_KEY: "admin-roleplay-key",
    OPENCODE_GO_API_KEY: "opencode-roleplay-key",
    ROLEPLAY_COMPACT_TRIGGER_TOKENS: "12000",
    ROLEPLAY_HARD_INPUT_TOKENS: "24000",
    ROLEPLAY_KEEP_RECENT_MESSAGES: "12",
    ...overrides,
  };

  env.ROLEPLAY_SESSION = {
    getByName(sessionId) {
      if (!storageBySession.has(sessionId)) {
        const storage = new FakeStorage();
        const ctx = {
          storage,
          waitUntil(promise) {
            waits.push(Promise.resolve(promise));
          },
        };
        storageBySession.set(sessionId, {
          instance: new RoleplaySession(ctx, env),
          storage,
        });
      }
      return {
        fetch(request) {
          return storageBySession.get(sessionId).instance.fetch(request);
        },
      };
    },
  };

  return {
    env,
    storageBySession,
    async waitForBackgroundWork() {
      await Promise.allSettled(waits.splice(0));
    },
  };
}

export function roleplayRequest(body, headers = {}) {
  return new Request("https://proxy.example/v1/roleplay", {
    method: "POST",
    headers: {
      Authorization: "Bearer admin-roleplay-key",
      "Content-Type": "application/json",
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

export async function withGlobalFetch(fetchImpl, operation) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  try {
    return await operation();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

export function completionResponse(model, content = "In character.") {
  return new Response(
    JSON.stringify({
      id: "chatcmpl-roleplay",
      object: "chat.completion",
      model,
      choices: [
        {
          index: 0,
          message: { role: "assistant", content },
          finish_reason: "stop",
        },
      ],
    }),
    { headers: { "Content-Type": "application/json" } },
  );
}

export { handleRoleplayEdgeRequest };
