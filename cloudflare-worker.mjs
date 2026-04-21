import { Container } from "@cloudflare/containers";

const API_ROUTE_PREFIXES = new Set([
  "azure",
  "cerebras",
  "chutes",
  "gemini",
  "gemma",
  "googleai",
  "groq",
  "hyperbolic",
  "nineteen",
  "openai",
  "opencode",
  "openrouter",
  "palm",
  "sambanova",
  "scaleway",
  "together",
  "xai",
]);
const CORS_ALLOWED_METHODS = "GET, POST, PUT, DELETE, PATCH, OPTIONS";
const CORS_DEFAULT_HEADERS = "Authorization, Content-Type, Accept, Origin, X-Requested-With";

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

function isApiRequestPath(pathname) {
  const stripped = pathname.replace(/^\/+|\/+$/g, "");
  if (!stripped) {
    return false;
  }

  if (stripped === "health") {
    return true;
  }

  const [firstSegment] = stripped.split("/", 1);
  return API_ROUTE_PREFIXES.has(firstSegment);
}

function buildCorsHeaders(request) {
  const origin = request.headers.get("Origin");
  const { pathname } = new URL(request.url);

  if (!origin || !isApiRequestPath(pathname)) {
    return null;
  }

  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": CORS_ALLOWED_METHODS,
    "Access-Control-Allow-Headers":
      request.headers.get("Access-Control-Request-Headers") ?? CORS_DEFAULT_HEADERS,
    "Access-Control-Max-Age": "86400",
  };
}

function appendVaryHeader(headers, value) {
  const current = headers.get("Vary");
  if (!current) {
    headers.set("Vary", value);
    return;
  }

  const values = current
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (!values.includes(value)) {
    values.push(value);
    headers.set("Vary", values.join(", "));
  }
}

function applyCorsHeaders(request, response) {
  const corsHeaders = buildCorsHeaders(request);
  if (!corsHeaders) {
    return response;
  }

  const responseWithCors = new Response(response.body, response);
  for (const [header, value] of Object.entries(corsHeaders)) {
    responseWithCors.headers.set(header, value);
  }
  appendVaryHeader(responseWithCors.headers, "Origin");
  return responseWithCors;
}

function buildPreflightResponse(request) {
  const headers = buildCorsHeaders(request) ?? {};
  const response = new Response(null, { status: 204 });

  for (const [header, value] of Object.entries(headers)) {
    response.headers.set(header, value);
  }
  response.headers.set("Allow", CORS_ALLOWED_METHODS);
  appendVaryHeader(response.headers, "Origin");
  return response;
}

export class MultiLLMProxyContainer extends Container {
  defaultPort = 8080;
  sleepAfter = "15m";
  envVars = collectContainerEnv(this.env);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS" && isApiRequestPath(new URL(request.url).pathname)) {
      return buildPreflightResponse(request);
    }

    try {
      const response = await env.MULTILLM_PROXY_CONTAINER.getByName("primary").fetch(request);
      return applyCorsHeaders(request, response);
    } catch (error) {
      if (!buildCorsHeaders(request)) {
        throw error;
      }

      console.error("Container fetch failed", error);
      return applyCorsHeaders(
        request,
        new Response(
          JSON.stringify({
            error: "Proxy unavailable",
            message: "The proxy container could not handle the request.",
          }),
          {
            status: 502,
            headers: {
              "Content-Type": "application/json",
            },
          },
        ),
      );
    }
  },
};
