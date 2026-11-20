/**
 * Standalone helper for issue #1000: no key-rotation / dual-key decrypt path
 * for SecretEncryptionUtil.
 *
 * Encodes a dual-key (current + previous) decrypt selection strategy so
 * encrypted secrets remain readable during rotation without immediate data loss.
 */

export interface Abdulrcrtw1000KeyMaterial {
  kid: string;
  key: string; // reference/id or material handle in real impl; kept abstract here
  status: 'current' | 'previous' | 'retired';
}

export interface Abdulrcrtw1000CipherEnvelope {
  kid?: string;
  ciphertext: string;
}

export interface Abdulrcrtw1000DecryptAttempt {
  kid: string;
  ok: boolean;
  error?: string;
}

export type Abdulrcrtw1000DecryptFn = (
  key: Abdulrcrtw1000KeyMaterial,
  envelope: Abdulrcrtw1000CipherEnvelope,
) => string;

export function abdulrcrtw1000SelectVerificationKeys(
  keys: Abdulrcrtw1000KeyMaterial[],
  envelope: Abdulrcrtw1000CipherEnvelope,
): Abdulrcrtw1000KeyMaterial[] {
  if (envelope.kid) {
    const match = keys.find(
      (k) => k.kid === envelope.kid && k.status !== 'retired',
    );
    return match ? [match] : [];
  }
  // No kid: try current first, then previous (overlap window), never retired.
  const current = keys.filter((k) => k.status === 'current');
  const previous = keys.filter((k) => k.status === 'previous');
  return [...current, ...previous];
}

export function abdulrcrtw1000DecryptWithDualKey(
  keys: Abdulrcrtw1000KeyMaterial[],
  envelope: Abdulrcrtw1000CipherEnvelope,
  decrypt: Abdulrcrtw1000DecryptFn,
): {
  plaintext: string;
  usedKid: string;
  attempts: Abdulrcrtw1000DecryptAttempt[];
} {
  const candidates = abdulrcrtw1000SelectVerificationKeys(keys, envelope);
  if (candidates.length === 0) {
    throw new Error('NO_USABLE_DECRYPTION_KEY');
  }
  const attempts: Abdulrcrtw1000DecryptAttempt[] = [];
  for (const key of candidates) {
    try {
      const plaintext = decrypt(key, envelope);
      attempts.push({ kid: key.kid, ok: true });
      return { plaintext, usedKid: key.kid, attempts };
    } catch (e) {
      attempts.push({
        kid: key.kid,
        ok: false,
        error: e instanceof Error ? e.message : 'decrypt_failed',
      });
    }
  }
  throw new Error('DECRYPTION_FAILED_WITH_ALL_KEYS');
}

export function abdulrcrtw1000NeedsReencrypt(
  usedKid: string,
  keys: Abdulrcrtw1000KeyMaterial[],
): boolean {
  const current = keys.find((k) => k.status === 'current');
  return !!current && usedKid !== current.kid;
}
