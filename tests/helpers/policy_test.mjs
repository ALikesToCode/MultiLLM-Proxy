/** Unit transports have an explicit authenticated durable account. */
import nativeTest from "node:test";
import { withDispatchPrincipal } from "../../worker/provider-dispatch.mjs";
import { dispatchEnv } from "./dispatch_fixture.mjs";
function policyTest(name, ...args) {
  const callback = args.pop();
  return nativeTest(name, ...args, (...values) => withDispatchPrincipal(dispatchEnv(),
    { authenticated: true, keyId: "fixture-reader" }, () => callback(...values)));
}
export default Object.assign(policyTest, nativeTest);
