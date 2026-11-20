# JWT Secret Rotation Strategy for Claim Tokens (abdulrcrtw-1002)

Standalone documentation helper for issue #1002: document and propose a rotation
strategy for `JWT_SECRET` used to sign claim tokens.

## Context

- Claim tokens are long-lived JWTs (default `CLAIM_TOKEN_EXPIRY` 30 days).
- Immediate `JWT_SECRET` rotation without overlap invalidates all outstanding tokens.
- No documented rotation procedure currently exists.

## Rotation goals

- Allow planned rotation without mass-invalidation of valid, unexpired claim tokens.
- Support emergency rotation with explicit invalidation/communication path.
- Avoid logging or exposing secret material.

## Proposed strategy (dual-secret overlap window)

### Configuration model

- `JWT_SECRET_CURRENT` (or existing `JWT_SECRET`): active signing key for newly issued tokens.
- `JWT_SECRET_PREVIOUS` (optional): verification-only key accepted during overlap.
- `JWT_KID` (optional): key id embedded in JWT header for deterministic key selection.

### Issuance and verification

1. **Sign** new tokens with `JWT_SECRET_CURRENT` (and set `kid` if used).
2. **Verify** tokens by trying `JWT_SECRET_CURRENT` first, then `JWT_SECRET_PREVIOUS` (or by `kid` lookup) until signature matches.
3. **Expiry still enforced:** verification must continue to reject expired tokens regardless of key validity.

### Planned rotation procedure

1. Deploy config with `PREVIOUS = old`, `CURRENT = new` (overlap enabled). New tokens signed with new key; old unexpired tokens still verify.
2. Keep overlap for at least `max(CLAIM_TOKEN_EXPIRY)` (or remaining max token lifetime) so all tokens signed with old key can naturally expire.
3. Remove `JWT_SECRET_PREVIOUS` after overlap window elapses and no valid tokens depend on it.
4. Audit logs/metrics for verification-fallback usage before removing previous key.

### Emergency rotation

- If compromise suspected, rotate to `CURRENT=new` without `PREVIOUS` (or revoke immediately) and accept that outstanding tokens become invalid; notify integrators and provide re-issuance flow.
- Prefer short claim token TTLs and/or revocation tracking to reduce blast radius.

## Implementation/documentation follow-ups (tracked separately)

- Add support for previous-key verification in token generation/verification providers.
- Document env vars and rotation runbook in ops/security docs.
- Add tests covering sign-with-current, verify-with-previous during overlap, and rejection after overlap removal.
