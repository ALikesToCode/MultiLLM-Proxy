-- NULL inherits SECRET_SCAN_DEFAULT (redact when unset).
ALTER TABLE control_users ADD COLUMN secret_scan_mode TEXT
  CHECK (secret_scan_mode IS NULL OR secret_scan_mode IN ('off', 'observe', 'redact', 'block'));
