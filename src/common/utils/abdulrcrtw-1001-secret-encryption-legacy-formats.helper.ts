/**
 * Standalone helper for issue #1001: legacy unprefixed/base64 secret formats
 * still silently supported in decrypt().
 *
 * Encodes the detection/migration-audit behavior needed to stop silently
 * accepting legacy ciphertext formats without an explicit migration path.
 */

export type Abdulrcrtw1001CiphertextFormat =
  | 'prefixed_v1'
  | 'legacy_base64'
  | 'legacy_unprefixed'
  | 'unknown';

export interface Abdulrcrtw1001ParseResult {
  format: Abdulrcrtw1001CiphertextFormat;
  isLegacy: boolean;
  requiresMigration: boolean;
  action: 'decrypt' | 'decrypt_and_reencrypt' | 'reject';
}

const PREFIXED_V1 = /^v1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+(?::[A-Za-z0-9+/=]+)?$/;
const BASE64ISH =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function abdulrcrtw1001ClassifyCiphertext(
  value: string,
): Abdulrcrtw1001ParseResult {
  if (PREFIXED_V1.test(value)) {
    return {
      format: 'prefixed_v1',
      isLegacy: false,
      requiresMigration: false,
      action: 'decrypt',
    };
  }
  if (value.length > 0 && BASE64ISH.test(value) && !value.includes(':')) {
    // Legacy base64 blob without version/field prefix.
    return {
      format: 'legacy_base64',
      isLegacy: true,
      requiresMigration: true,
      action: 'decrypt_and_reencrypt',
    };
  }
  if (value.length > 0 && !value.startsWith('v1:')) {
    // Legacy unprefixed/non-canonical format kept for backward compatibility in older data.
    return {
      format: 'legacy_unprefixed',
      isLegacy: true,
      requiresMigration: true,
      action: 'decrypt_and_reencrypt',
    };
  }
  return {
    format: 'unknown',
    isLegacy: false,
    requiresMigration: false,
    action: 'reject',
  };
}

export function abdulrcrtw1001ShouldLogLegacyAcceptance(
  result: Abdulrcrtw1001ParseResult,
): boolean {
  // Silent acceptance is risky; legacy decrypts should be observable for migration tracking.
  return result.isLegacy && result.action === 'decrypt_and_reencrypt';
}

export function abdulrcrtw1001MigrationAudit(records: string[]) {
  const counts = {
    prefixed_v1: 0,
    legacy_base64: 0,
    legacy_unprefixed: 0,
    unknown: 0,
  };
  for (const r of records)
    counts[abdulrcrtw1001ClassifyCiphertext(r).format] += 1;
  return {
    counts,
    migrationComplete:
      counts.legacy_base64 === 0 && counts.legacy_unprefixed === 0,
  };
}
