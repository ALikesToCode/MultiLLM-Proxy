/** Build every provider SDK/binding double here, including nested SDK handles. */
import assert from "node:assert/strict";
import { networkAdmitted } from "../../worker/dispatch-network.mjs";

export function providerBinding(binding) {
  const wrapped = new WeakMap();
  function guard(value) {
    if (!value || Array.isArray(value) || typeof value !== "object" && typeof value !== "function") return value;
    if (wrapped.has(value)) return wrapped.get(value);
    const proxy = new Proxy(value, {
      get(target, name, receiver) {
        const member = Reflect.get(target, name, receiver);
        return name === "constructor" ? member : guard(member);
      },
      apply(target, receiver, args) {
        assert.ok(networkAdmitted(), "Provider binding outside provider chokepoint");
        const result = Reflect.apply(target, receiver, args);
        // Synchronous SDK factories return handles whose methods need their own
        // admission check. Async responses and streams remain ordinary results.
        return result && Object.getPrototypeOf(result) === Object.prototype ? guard(result) : result;
      },
    });
    wrapped.set(value, proxy);
    wrapped.set(proxy, proxy);
    return proxy;
  }
  return guard(binding);
}
