import crypto from 'node:crypto';
import type { EncryptedPayload, WrappedKey } from './types.ts';

const AES_GCM_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH_BYTES = 12; // 96-bit standard IV for GCM
const KEY_LENGTH_BYTES = 32; // 256-bit key for AES-256

/**
 * Generates a cryptographically secure random 256-bit Data Key (K_data).
 */
export function generateDataKey(): Uint8Array {
  return new Uint8Array(crypto.randomBytes(KEY_LENGTH_BYTES));
}

/**
 * Generates arbitrary cryptographically secure random bytes.
 */
export function generateRandomBytes(length: number): Uint8Array {
  return new Uint8Array(crypto.randomBytes(length));
}

/**
 * Encrypts arbitrary plaintext data using AES-256-GCM.
 *
 * @param plaintext The payload to encrypt (string or Uint8Array).
 * @param key 32-byte AES key.
 * @param aad Optional Additional Authenticated Data.
 * @returns EncryptedPayload containing Base64 encoded ciphertext, IV, tag, and AAD.
 */
export function encryptVault(
  plaintext: Uint8Array | string,
  key: Uint8Array,
  aad?: Uint8Array | string
): EncryptedPayload {
  if (key.length !== KEY_LENGTH_BYTES) {
    throw new Error(`AES-256 key must be exactly ${KEY_LENGTH_BYTES} bytes, got ${key.length}`);
  }

  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(AES_GCM_ALGORITHM, key, iv);

  let aadBuffer: Buffer | undefined;
  if (aad !== undefined) {
    aadBuffer = typeof aad === 'string' ? Buffer.from(aad, 'utf-8') : Buffer.from(aad);
    cipher.setAAD(aadBuffer);
  }

  const inputBuffer = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf-8') : Buffer.from(plaintext);
  const ciphertext = Buffer.concat([cipher.update(inputBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    aad: aadBuffer ? aadBuffer.toString('base64') : undefined,
  };
}

/**
 * Decrypts an EncryptedPayload using AES-256-GCM and verifies authentication tag.
 *
 * @param payload The encrypted package.
 * @param key 32-byte AES key.
 * @param aad Optional Additional Authenticated Data (must match encryption AAD).
 * @returns Decrypted plaintext as a Uint8Array.
 * @throws Error if authentication tag verification fails (tampered data or wrong key).
 */
export function decryptVault(
  payload: EncryptedPayload,
  key: Uint8Array,
  aad?: Uint8Array | string
): Uint8Array {
  if (key.length !== KEY_LENGTH_BYTES) {
    throw new Error(`AES-256 key must be exactly ${KEY_LENGTH_BYTES} bytes, got ${key.length}`);
  }

  const iv = Buffer.from(payload.iv, 'base64');
  const tag = Buffer.from(payload.tag, 'base64');
  const ciphertext = Buffer.from(payload.ciphertext, 'base64');

  const decipher = crypto.createDecipheriv(AES_GCM_ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  if (aad !== undefined) {
    const aadBuffer = typeof aad === 'string' ? Buffer.from(aad, 'utf-8') : Buffer.from(aad);
    decipher.setAAD(aadBuffer);
  } else if (payload.aad !== undefined) {
    decipher.setAAD(Buffer.from(payload.aad, 'base64'));
  }

  try {
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return new Uint8Array(decrypted);
  } catch (err: any) {
    throw new Error(`Vault decryption authentication failed: ${err.message || 'Invalid key or corrupted ciphertext'}`);
  }
}

/**
 * Wraps a target key (e.g. K_data) under a wrapping key (e.g. K_pw or K_rec) using AES-256-GCM.
 *
 * @param keyToWrap The key to protect (typically 32 bytes).
 * @param wrappingKey The 32-byte wrapping key.
 * @returns WrappedKey containing Base64 encoded ciphertext, IV, and auth tag.
 */
export function wrapKey(keyToWrap: Uint8Array, wrappingKey: Uint8Array): WrappedKey {
  const enc = encryptVault(keyToWrap, wrappingKey);
  return {
    wrappedKey: enc.ciphertext,
    iv: enc.iv,
    tag: enc.tag,
  };
}

/**
 * Unwraps a wrapped key using AES-256-GCM and verifies the authentication tag.
 *
 * @param wrapped The wrapped key structure.
 * @param wrappingKey The 32-byte wrapping key.
 * @returns The original unwrapped key as a Uint8Array.
 * @throws Error if authentication tag check fails (e.g. wrong password derivation).
 */
export function unwrapKey(wrapped: WrappedKey, wrappingKey: Uint8Array): Uint8Array {
  return decryptVault(
    {
      ciphertext: wrapped.wrappedKey,
      iv: wrapped.iv,
      tag: wrapped.tag,
    },
    wrappingKey
  );
}
