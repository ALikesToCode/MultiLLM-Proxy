/** Offline-compatible MCP contracts; no provider, storage or permission side effects. */
import { fail, isRecord, KnowledgeError } from "./contracts.mjs";

export const CONTRACT_VERSION = "1.0.0";
const MAX_CANONICAL_BYTES = 256 * 1024;
const MAX_DEPTH = 64;
const MAX_NODES = 65536;
let warned = false;

export function digestsEnabled(value, warn = message => console.warn(message)) {
  if (typeof value === "boolean") return value;
  if (value === undefined || value === null) return false;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (["", "false", "0"].includes(normalized)) return false;
    if (["true", "1"].includes(normalized)) return true;
  }
  if (!warned) {
    warn("Invalid MCP_CONTRACT_DIGESTS_ENABLED; contract digests are disabled.");
    warned = true;
  }
  return false;
}

const scalarOrder = (a, b) => {
  const left = Array.from(a, char => char.codePointAt(0));
  const right = Array.from(b, char => char.codePointAt(0));
  for (let i = 0; i < Math.min(left.length, right.length); i++) if (left[i] !== right[i]) return left[i] - right[i];
  return left.length - right.length;
};
const text = value => {
  if (!value.isWellFormed()) throw new Error("Contract strings must contain Unicode scalar values.");
  return value;
};

export function canonicalValue(value) {
  let remaining = MAX_NODES;
  const node = (item, depth) => {
    if (depth > MAX_DEPTH || --remaining < 0) throw new Error("Contract exceeds canonical depth or node limits.");
    if (item === null) return ["null"];
    if (typeof item === "boolean") return ["boolean", item];
    if (typeof item === "number") {
      if (!Number.isFinite(item) || Math.abs(item) > Number.MAX_SAFE_INTEGER) throw new Error("Contract numbers must be finite and within the interoperable range.");
      const bytes = new ArrayBuffer(8);
      new DataView(bytes).setFloat64(0, item === 0 ? 0 : item, false);
      return ["number", Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, "0")).join("")];
    }
    if (typeof item === "string") return ["string", text(item)];
    if (Array.isArray(item)) return ["array", item.map(child => node(child, depth + 1))];
    if (isRecord(item) && Object.getPrototypeOf(item) === Object.prototype) {
      return ["object", Object.keys(item).sort(scalarOrder).map(key => [text(key), node(item[key], depth + 1)])];
    }
    throw new Error("Contract contains a non-JSON value.");
  };
  const encoded = JSON.stringify(node(value, 0));
  if (new TextEncoder().encode(encoded).length > MAX_CANONICAL_BYTES) throw new Error("Contract exceeds canonical byte limit.");
  return encoded;
}

function contractPayload(definition, contractVersion) {
  if (!isRecord(definition) || typeof definition.name !== "string" || !Object.hasOwn(definition, "inputSchema")) throw new Error("A tool contract requires a name and inputSchema.");
  return { name: definition.name, inputSchema: definition.inputSchema, outputSchema: definition.outputSchema ?? null, contractVersion };
}

export const canonicalContract = (definition, contractVersion = CONTRACT_VERSION) => canonicalValue(contractPayload(definition, contractVersion));
const sha256 = async value => {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, "0")).join("");
};
export const contractDigest = (definition, contractVersion = CONTRACT_VERSION) => sha256(canonicalContract(definition, contractVersion));
export const catalogueDigest = (definitions, contractVersion = CONTRACT_VERSION) => sha256(canonicalValue(
  [...definitions].sort((a, b) => scalarOrder(a.name, b.name)).map(tool => contractPayload(tool, contractVersion))));

export async function discoveryContract(entries, scopes, { toolsets = null, enabled = false } = {}) {
  const tools = entries.filter(entry => (scopes.includes("admin") || scopes.includes(entry.scope))
    && (toolsets === null || toolsets.includes(entry.toolset))).map(entry => entry.definition);
  if (!enabled) return { tools };
  return { tools: await Promise.all(tools.map(async tool => ({ ...tool, _meta: { ...tool._meta, contract_digest: await contractDigest(tool) } }))),
    _meta: { contract_digest: await catalogueDigest(tools) } };
}

export async function checkContractPin(definition, pin, { enabled = false } = {}) {
  if (!enabled || pin === undefined || pin === null) return;
  if (typeof pin !== "string" || pin.length !== 64 || pin !== await contractDigest(definition)) {
    fail("mcp_contract_mismatch", "The pinned MCP tool contract has changed. Refresh discovery.", 409);
  }
}


/** Translate only a local pin rejection for the public MCP HTTP boundary. */
export async function contractPinMismatch(definition, pin, flag) {
  try {
    await checkContractPin(definition, pin, { enabled: digestsEnabled(flag) });
    return null;
  } catch (error) {
    if (!(error instanceof KnowledgeError) || error.code !== "mcp_contract_mismatch") throw error;
    return { code: error.code, message: error.message, status: error.status };
  }
}
