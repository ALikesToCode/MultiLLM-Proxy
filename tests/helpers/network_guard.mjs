import net from "node:net";
/** Suite-wide runtime guard; replacing fetch cannot replace the admission check. */
import { networkAdmitted, connectionAdmitted } from "../../worker/dispatch-network.mjs";
const guarded = new WeakSet();
function wrap(transport) {
  if (guarded.has(transport)) return transport;
  const checked = function (...args) {
    if (!networkAdmitted(args[0])) throw new Error("Outbound connection outside provider chokepoint");
    return transport.apply(this, args);
  };
  guarded.add(checked);
  return checked;
}
let transport = wrap(globalThis.fetch);
Object.defineProperty(globalThis, "fetch", { configurable: false, get: () => transport,
  set: value => { transport = wrap(value); } });
if (typeof globalThis.connect === "function") {
  let connect = wrap(globalThis.connect);
  Object.defineProperty(globalThis, "connect", { configurable: false, get: () => connect,
    set: value => { connect = wrap(value); } });
}

// Only explicitly registered local D1 bridge ports are infrastructure traffic.
const fixturePorts = new Set();
export function registerFixtureOrigin(url) {
  const target = new URL(url);
  if (!["127.0.0.1", "[::1]", "localhost"].includes(target.hostname)) throw Error("Non-local test fixture");
  fixturePorts.add(String(target.port));
  return () => fixturePorts.delete(String(target.port));
}
const socketConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const options = Array.isArray(args[0]) ? args[0][0] : args[0];
  const host = typeof options === "object" ? options.host : args[1];
  const port = typeof options === "object" ? options.port : options;
  const fixtureRpc = ["127.0.0.1", "::1", "localhost"].includes(host) && fixturePorts.has(String(port));
  if (!connectionAdmitted(host, port) && !fixtureRpc) throw new Error("Outbound connection outside provider chokepoint");
  return socketConnect.apply(this, args);
};
