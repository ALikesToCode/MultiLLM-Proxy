/** Fixed request-scoped hooks. Registrations are code, never environment-provided plugins. */
export const GATEWAY_HOOKS = Object.freeze(["authorize", "admit", "before_dispatch", "observe", "finalize"]);

export function createGatewayLifecycle(collaborators = []) {
  const registrations = Object.freeze([...collaborators]);
  let finalization;
  const invoke = async (name, context) => {
    for (const collaborator of registrations) {
      if (typeof collaborator[name] === "function") await collaborator[name](context);
    }
  };
  return Object.freeze(Object.fromEntries(GATEWAY_HOOKS.map(name => [name, context => {
    if (name !== "finalize") return invoke(name, context);
    // Assign before invoking any asynchronous collaborator, including concurrent callers.
    return finalization ??= Promise.resolve().then(async () => {
      let failure;
      for (const collaborator of registrations) {
        try { await collaborator.finalize?.(context); } catch (error) { failure ??= error; }
      }
      if (failure) throw failure;
    });
  }])));
}
