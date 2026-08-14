export class RoleplayRequestError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.name = "RoleplayRequestError";
    this.status = status;
  }
}

export function boundedString(
  value,
  name,
  maximum,
  { required = false } = {},
) {
  if (value === undefined || value === null) {
    if (required) {
      throw new RoleplayRequestError(`${name} is required`);
    }
    return "";
  }
  if (typeof value !== "string") {
    throw new RoleplayRequestError(`${name} must be a string`);
  }
  const normalized = value.trim();
  if (required && !normalized) {
    throw new RoleplayRequestError(`${name} must not be empty`);
  }
  if (normalized.length > maximum) {
    throw new RoleplayRequestError(
      `${name} must be at most ${maximum} characters`,
    );
  }
  return normalized;
}
