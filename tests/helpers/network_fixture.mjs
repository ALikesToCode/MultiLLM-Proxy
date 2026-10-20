import { controlNetwork } from "../../worker/dispatch-network.mjs";
export function mockFetch(t, implementation) {
  const previous = globalThis.fetch;
  globalThis.fetch = implementation;
  t.after(() => { globalThis.fetch = previous; });
}
export const clientNetwork = (url, run) => controlNetwork(url, run);
