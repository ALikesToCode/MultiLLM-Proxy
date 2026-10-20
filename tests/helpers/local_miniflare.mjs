/** Register only each disposable D1 server's exact loopback port with the guard. */
export * from "miniflare";
import { Miniflare as NativeMiniflare } from "miniflare";
import { registerFixtureOrigin } from "./network_guard.mjs";
export class Miniflare extends NativeMiniflare {
  constructor(...args) {
    super(...args);
    this.fixtureRegistration = this.ready.then(registerFixtureOrigin);
  }
  async getD1Database(...args) {
    await this.fixtureRegistration;
    return super.getD1Database(...args);
  }
  async dispose() {
    const unregister = await this.fixtureRegistration.catch(() => null);
    try { return await super.dispose(); }
    finally { unregister?.(); }
  }
}
