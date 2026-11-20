# KMS Data Key Persistence Audit (abdulrcrtw-999)

Standalone documentation helper for issue #999: `SecretEncryptionUtil` generates
a random data key on startup when KMS key env vars are absent, making previously
encrypted secrets undecryptable after restart.

## Problem

- Ephemeral/in-memory data key generation on each process start means any secret
  encrypted with the prior key cannot be decrypted after a restart or redeploy.
- Encrypted-at-rest data (e.g. webhook secrets, other sensitive fields) becomes
  permanently unreadable unless the key material is durably persisted and loaded.

## Expected behavior

- **Production:** encryption keys must come from stable configuration or a KMS
  (env/secret manager/HSM/KMS) so the same logical key (or versioned key set) is
  available across restarts and instances.
- **Fail fast:** if required key configuration is missing in non-development
  environments, startup should fail with a clear error rather than silently
  generating a transient key.
- **Development-only fallback:** any random-key fallback must be explicitly gated
  (e.g. `NODE_ENV=development`/local-only flag), loudly warned, and never used
  for durable/persisted secrets.

## Mitigations / recommendations

1. Require `ENCRYPTION_KEY`/KMS configuration in staging/production; refuse to
   boot without it (or without a configured KMS provider).
2. Support key versioning/identifiers (`kid`) in ciphertext envelopes so future
   rotations and dual-key decrypt paths (see #1000) are possible.
3. Persist and back up key material according to operational policy; never log keys.
4. Add startup/health checks and tests asserting restart-safe decrypt for known
   ciphertext when configured with the same key source.
5. Document operational runbook for key provisioning, rotation, and recovery.
