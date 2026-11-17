import crypto from 'node:crypto';
import { argon2id } from '@noble/hashes/argon2.js';
import type { Argon2Params } from './types.ts';

// Production defaults (RFC 9106 recommended for password hashing & key derivation)
export const DEFAULT_ARGON2_PARAMS: Required<Argon2Params> = {
  timeCost: 3,          // 3 iterations
  memoryCostKiB: 65536, // 64 MiB
  parallelism: 1,       // 1 thread
  keyLength: 32,        // 256-bit AES key
};

// Fast testing defaults for rapid unit test execution
export const FAST_TEST_ARGON2_PARAMS: Required<Argon2Params> = {
  timeCost: 2,
  memoryCostKiB: 512,  // 512 KiB
  parallelism: 1,
  keyLength: 32,
};

/**
 * Generates a random cryptographic salt.
 *
 * @param length Length in bytes (defaults to 16 bytes).
 */
export function generateSalt(length: number = 16): Uint8Array {
  return new Uint8Array(crypto.randomBytes(length));
}

/**
 * Derives a 256-bit symmetric key (K_pw) from a user password and salt using Argon2id.
 *
 * @param password The user password (string or Uint8Array).
 * @param salt The cryptographic salt (string or Uint8Array, minimum 8 bytes).
 * @param options Optional Argon2id parameters (iterations, memory, parallelism, dkLen).
 * @returns 32-byte derived key as Uint8Array.
 */
export function derivePasswordKey(
  password: string | Uint8Array,
  salt: string | Uint8Array,
  options?: Argon2Params
): Uint8Array {
  const pwdBytes = typeof password === 'string' ? new TextEncoder().encode(password) : password;
  const saltBytes = typeof salt === 'string' ? new TextEncoder().encode(salt) : salt;

  if (saltBytes.length < 8) {
    throw new Error(`Argon2id requires a salt of at least 8 bytes, got ${saltBytes.length}`);
  }

  const t = options?.timeCost ?? DEFAULT_ARGON2_PARAMS.timeCost;
  const m = options?.memoryCostKiB ?? DEFAULT_ARGON2_PARAMS.memoryCostKiB;
  const p = options?.parallelism ?? DEFAULT_ARGON2_PARAMS.parallelism;
  const dkLen = options?.keyLength ?? DEFAULT_ARGON2_PARAMS.keyLength;

  const derived = argon2id(pwdBytes, saltBytes, {
    t,
    m,
    p,
    dkLen,
  });

  return new Uint8Array(derived);
}
