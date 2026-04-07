import { Container } from "@cloudflare/containers";

const DIRECT_ENV_KEYS = [
  "ADMIN_USERNAME",
  "ADMIN_API_KEY",
  "FLASK_SECRET_KEY",
  "JWT_SECRET",
  "PROJECT_ID",
  "LOCATION",
  "GOOGLE_ENDPOINT",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GOOGLE_APPLICATION_CREDENTIALS_JSON",
  "OPENAI_API_KEY",
  "CEREBRAS_API_KEY",
  "XAI_API_KEY",
  "TOGETHER_API_KEY",
  "AZURE_API_KEY",
  "SCALEWAY_API_KEY",
  "HYPERBOLIC_API_KEY",
  "SAMBANOVA_API_KEY",
  "OPENROUTER_API_KEY",
  "OPENCODE_API_KEY",
  "OPENROUTER_SITE_URL",
  "OPENROUTER_APP_NAME",
  "OPENROUTER_REFERER",
  "PALM_API_KEY",
  "NINETEEN_API_KEY",
  "CHUTES_API_TOKEN",
  "GEMINI_API_KEY",
  "APP_NAME",
  "GUNICORN_WORKERS",
  "GUNICORN_THREADS",
  "GUNICORN_TIMEOUT",
];

const DYNAMIC_ENV_PATTERNS = [/^GROQ_API_KEY_\d+$/];

function shouldPassThroughKey(key) {
  return DIRECT_ENV_KEYS.includes(key) || DYNAMIC_ENV_PATTERNS.some((pattern) => pattern.test(key));
}

function collectContainerEnv(source) {
  const envVars = {
    FLASK_ENV: source.FLASK_ENV ?? "production",
    SERVER_HOST: "0.0.0.0",
    SERVER_PORT: "8080",
    PYTHONUNBUFFERED: "1",
  };

  for (const [key, value] of Object.entries(source)) {
    if (!shouldPassThroughKey(key)) {
      continue;
    }

    if (value === undefined || value === null || value === "") {
      continue;
    }

    envVars[key] = String(value);
  }

  return envVars;
}

export class MultiLLMProxyContainer extends Container {
  defaultPort = 8080;
  sleepAfter = "15m";
  envVars = collectContainerEnv(this.env);
}

export default {
  async fetch(request, env) {
    return env.MULTILLM_PROXY_CONTAINER.getByName("primary").fetch(request);
  },
};
