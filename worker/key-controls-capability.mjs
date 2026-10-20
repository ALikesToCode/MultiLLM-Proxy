/** Code capability, never an operator feature flag. */
export const KEY_CONTROLS = Object.freeze({ protocol: 2, enforcement: true });
export const controlled = row => row?.official_only != null || row?.forced_provider_preferences != null;
export function expansionFence(row) {
  if (!KEY_CONTROLS.enforcement && controlled(row)) {
    const error = new Error("key_controls_require_upgrade"); error.code = "key_controls_require_upgrade"; error.status = 503; throw error;
  }
  return row;
}
