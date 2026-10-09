/** Explicit immutable authority boundaries; registration grants no permissions. */
export const MAX_INTEGER = Number.MAX_SAFE_INTEGER;

function opaque(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 128 || /[^A-Za-z0-9_:.\-]/.test(value)) {
    throw new TypeError("Invalid opaque identifier");
  }
}
function integer(value, maximum = MAX_INTEGER - 1) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) throw new TypeError("Invalid bounded integer");
}
function fields(data, required, optional = []) {
  if (!data || typeof data !== "object" || Array.isArray(data) ||
      required.some(name => !(name in data)) ||
      Object.keys(data).some(name => !required.includes(name) && !optional.includes(name))) {
    throw new TypeError("Invalid contract fields");
  }
}
function context(value) {
  if (!(value instanceof TenantContext) || !Object.isFrozen(value)) throw new TypeError("TenantContext required");
}

export class TenantContext {
  constructor(data) {
    fields(data, ["principal_id"], ["org_id", "team_id", "grants_revision"]);
    const { principal_id, org_id = null, team_id = null, grants_revision = 0 } = data;
    opaque(principal_id);
    integer(grants_revision);
    for (const value of [org_id, team_id]) if (value !== null) opaque(value);
    if (team_id !== null && org_id === null) throw new TypeError("Team requires organisation scope");
    Object.assign(this, { principal_id, org_id, team_id, grants_revision });
    Object.freeze(this);
  }
}

export class IdentityAssertion {
  constructor(data) {
    fields(data, ["issuer_id", "subject_id", "audience_id", "request_id", "nonce_id", "expires_at", "verified"]);
    for (const name of ["issuer_id", "subject_id", "audience_id", "request_id", "nonce_id"]) opaque(data[name]);
    integer(data.expires_at);
    if (data.verified !== true || data.expires_at === 0) throw new TypeError("Verified identity assertion required");
    Object.assign(this, data);
    Object.freeze(this);
  }
}

export class AuthorityOperation {
  constructor(data) {
    fields(data, ["context", "scoped_id", "revision", "operation_id"], ["amount"]);
    context(data.context);
    opaque(data.scoped_id);
    opaque(data.operation_id);
    integer(data.revision);
    integer(data.amount === undefined ? 0 : data.amount);
    Object.assign(this, { ...data, amount: data.amount === undefined ? 0 : data.amount });
    Object.freeze(this);
  }
}

export class AuthorityResult {
  constructor(data) {
    fields(data, ["context", "scoped_id", "revision", "operation_id", "allowed"]);
    context(data.context);
    opaque(data.scoped_id);
    opaque(data.operation_id);
    integer(data.revision, MAX_INTEGER);
    if (typeof data.allowed !== "boolean") throw new TypeError("Boolean decision required");
    Object.assign(this, data);
    Object.freeze(this);
  }
}

export class PaymentEvent {
  constructor(data) {
    fields(data, ["context", "scoped_id", "revision", "idempotency_id", "processor_id", "event_id", "kind", "currency", "amount", "verified"]);
    new AuthorityOperation({ context: data.context, scoped_id: data.scoped_id, revision: data.revision,
      operation_id: data.idempotency_id, amount: data.amount });
    opaque(data.processor_id);
    opaque(data.event_id);
    if (data.verified !== true || !["credit", "refund", "dispute"].includes(data.kind) ||
        typeof data.currency !== "string" || data.currency.length !== 3 || /[^A-Z]/.test(data.currency)) {
      throw new TypeError("Verified payment event required");
    }
    Object.assign(this, data);
    Object.freeze(this);
  }
}

/** @typedef {{reserve: function(AuthorityOperation): (AuthorityResult|Promise<AuthorityResult>),
 * commit: function(AuthorityOperation): (AuthorityResult|Promise<AuthorityResult>),
 * reconcile: function(AuthorityOperation): (AuthorityResult|Promise<AuthorityResult>)}} QuotaAuthority */
/** @typedef {QuotaAuthority} CreditAuthority */
/** @typedef {function(AuthorityOperation): (TenantContext|Promise<TenantContext>)} TenantAuthority */
/** @typedef {function(IdentityAssertion, AuthorityOperation): (TenantContext|Promise<TenantContext>)} IdentityAuthority */
/** @typedef {function(PaymentEvent): (AuthorityResult|Promise<AuthorityResult>)} PaymentCallback */

export class AuthorityDenied extends Error {}

export function legacyTenant(operation) {
  requireOperation(operation);
  if (operation.context.org_id !== null || operation.context.team_id !== null) throw new AuthorityDenied("tenant_scope_denied");
  return operation.context;
}

/** @param {{tenant?: TenantAuthority|null, identity?: IdentityAuthority|null,
 * quota?: QuotaAuthority|null, credit?: CreditAuthority|null, payment?: PaymentCallback|null}} [options] */
export function registerEnterpriseAdapters(options = {}) {
  fields(options, [], ["tenant", "identity", "quota", "credit", "payment"]);
  const { tenant = legacyTenant, identity = null, quota = null, credit = null, payment = null } = options;
  for (const callback of [tenant, identity, payment]) {
    if (callback !== null && typeof callback !== "function") throw new TypeError("Explicit authority function required");
  }
  for (const authority of [quota, credit]) {
    if (authority !== null && ["reserve", "commit", "reconcile"].some(name => typeof authority[name] !== "function")) {
      throw new TypeError("Complete reserve/commit/reconcile authority required");
    }
  }
  return Object.freeze({ tenant, identity, quota, credit, payment });
}

function requireOperation(value) {
  if (!(value instanceof AuthorityOperation) || !Object.isFrozen(value)) throw new TypeError("AuthorityOperation required");
}
function sameContext(left, right) {
  return left instanceof TenantContext && Object.isFrozen(left) &&
    ["principal_id", "org_id", "team_id", "grants_revision"].every(name => left[name] === right[name]);
}
function boundContext(value, operation) {
  if (!sameContext(value, operation.context)) throw new AuthorityDenied("authority_scope_mismatch");
  return value;
}
function boundResult(value, operation) {
  if (!(value instanceof AuthorityResult) || !Object.isFrozen(value) || !value.allowed ||
      !sameContext(value.context, operation.context) || value.scoped_id !== operation.scoped_id ||
      value.operation_id !== operation.operation_id || value.revision !== operation.revision + 1) {
    throw new AuthorityDenied("authority_decision_denied");
  }
  return value;
}

export async function resolveTenant(adapters, operation) {
  requireOperation(operation);
  if (!adapters.tenant) throw new AuthorityDenied("authority_unavailable");
  return boundContext(await adapters.tenant(operation), operation);
}
export async function resolveIdentity(adapters, assertion, operation) {
  requireOperation(operation);
  if (!(assertion instanceof IdentityAssertion) || !Object.isFrozen(assertion) || assertion.verified !== true) {
    throw new TypeError("Verified IdentityAssertion required");
  }
  if (!adapters.identity) throw new AuthorityDenied("authority_unavailable");
  return boundContext(await adapters.identity(assertion, operation), operation);
}
export async function callAuthority(adapters, authority, action, operation) {
  requireOperation(operation);
  if (!["quota", "credit"].includes(authority) || !["reserve", "commit", "reconcile"].includes(action)) {
    throw new TypeError("Unknown authority operation");
  }
  const target = authority === "quota" ? adapters.quota : adapters.credit;
  if (!target) throw new AuthorityDenied("authority_unavailable");
  return boundResult(await target[action](operation), operation);
}
export async function deliverPayment(adapters, event) {
  if (!(event instanceof PaymentEvent) || !Object.isFrozen(event) || event.verified !== true) throw new TypeError("Verified PaymentEvent required");
  if (!adapters.payment) throw new AuthorityDenied("authority_unavailable");
  const operation = new AuthorityOperation({ context: event.context, scoped_id: event.scoped_id,
    revision: event.revision, operation_id: event.idempotency_id, amount: event.amount });
  return boundResult(await adapters.payment(event), operation);
}

let warned = false;
export function previewEnabled(env = {}, warn = message => console.warn(message)) {
  const raw = env.ENTERPRISE_PREVIEW_ENABLED;
  const flag = raw === undefined ? "" : typeof raw === "string" ? raw.trim().toLowerCase() : "invalid";
  if (["", "0", "false", "no", "off"].includes(flag)) return false;
  if (["1", "true", "yes", "on"].includes(flag)) return true;
  if (!warned) { warned = true; warn("Invalid ENTERPRISE_PREVIEW_ENABLED; enterprise preview disabled"); }
  return false;
}
export function previewDescriptor(adapters) {
  return { version: 1, dry_run: true, activation: false,
    contracts: ["TenantContext", "IdentityAssertion", "QuotaAuthority", "CreditAuthority", "PaymentEvent"],
    authorities: Object.fromEntries(["tenant", "identity", "quota", "credit", "payment"].map(name => [name, adapters[name] !== null])),
    operations: ["reserve", "commit", "reconcile"], missing_authority: "denied" };
}
