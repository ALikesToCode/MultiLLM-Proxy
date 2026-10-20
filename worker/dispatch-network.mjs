/** Network capabilities last only for one admitted transport operation. */
import { AsyncLocalStorage } from "node:async_hooks";
const network = new AsyncLocalStorage();
export const networkAdmitted = input => {
  const scope = network.getStore();
  if (!scope?.active) return false;
  if (!scope.url) return true;
  if (!input) return false;
  try { return new URL(typeof input === "string" || input instanceof URL ? input : input.url, "https://gateway.fixture").href === scope.url; }
  catch { return false; }
};
export const connectionAdmitted = (host, port) => {
  const scope = network.getStore();
  if (!scope?.active) return false;
  if (!scope.url) return true;
  const target = new URL(scope.url);
  return host === target.hostname && Number(port) === Number(target.port || (target.protocol === "https:" ? 443 : 80));
};
function scoped(scope, run) {
  return network.run(scope, () => {
    try {
      const result = run();
      if (result && typeof result.then === "function") return Promise.resolve(result).finally(() => { scope.active = false; });
      scope.active = false;
      return result;
    } catch (error) { scope.active = false; throw error; }
  });
}
export const admittedNetwork = run => scoped({ active: true }, run);
/** Certificate discovery, configured content-free alerts and browser test clients
 * are control traffic. This scope authorizes only their exact destination. */
export const controlNetwork = (url, run) => scoped({ active: true, url: new URL(url, "https://gateway.fixture").href }, run);
