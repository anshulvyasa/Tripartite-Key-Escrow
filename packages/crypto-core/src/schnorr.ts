import crypto from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1.js';
import type { SchnorrKeyPair, SchnorrChallenge } from './types.ts';

/**
 * Serializes a SchnorrChallenge into a canonical byte array for signing and verification.
 */
export function serializeChallenge(challenge: SchnorrChallenge | Uint8Array | string): Uint8Array {
  if (challenge instanceof Uint8Array) {
    return challenge;
  }
  if (typeof challenge === 'string') {
    return new TextEncoder().encode(challenge);
  }
  // Canonical string representation for structured challenge object
  const canonical = JSON.stringify({
    context: challenge.context ?? '',
    nonce: challenge.nonce,
    timestamp: challenge.timestamp,
  });
  return new TextEncoder().encode(canonical);
}

/**
 * Generates a local Schnorr recovery identity key pair (sk_rec, pk_rec).
 * The client keeps the private key locally and registers only the public key with the escrow.
 *
 * @returns SchnorrKeyPair with privateKey, publicKey, and their hex representations.
 */
export function generateSchnorrKeyPair(): SchnorrKeyPair {
  const { secretKey, publicKey } = schnorr.keygen();
  return {
    privateKey: secretKey,
    publicKey: publicKey,
    privateKeyHex: Buffer.from(secretKey).toString('hex'),
    publicKeyHex: Buffer.from(publicKey).toString('hex'),
  };
}

/**
 * Creates a fresh challenge for zero-knowledge challenge-response authentication.
 * Issued by the Escrow Cluster coordinator to the recovering client.
 *
 * @param context Optional context string (e.g. user ID or session ID).
 * @returns SchnorrChallenge containing 32-byte random nonce in hex and current timestamp.
 */
export function createSchnorrChallenge(context?: string): SchnorrChallenge {
  const nonce = crypto.randomBytes(32).toString('hex');
  return {
    nonce,
    timestamp: Date.now(),
    context,
  };
}

/**
 * Signs a challenge using the client's local Schnorr private key.
 *
 * @param challenge The challenge object, string, or byte array issued by the escrow.
 * @param privateKey The client's private key (Uint8Array or hex string).
 * @returns 64-byte BIP-340 Schnorr signature encoded as a hex string.
 */
export function signSchnorrChallenge(
  challenge: SchnorrChallenge | Uint8Array | string,
  privateKey: Uint8Array | string
): string {
  const privKeyBytes = typeof privateKey === 'string' ? Buffer.from(privateKey, 'hex') : privateKey;
  const msgBytes = serializeChallenge(challenge);

  // Generates 64-byte BIP-340 Schnorr signature
  const signature = schnorr.sign(msgBytes, privKeyBytes);
  return Buffer.from(signature).toString('hex');
}

/**
 * Verifies a Schnorr challenge-response signature against the client's registered public key.
 * Used by Escrow Nodes to authenticate the client without obtaining any private key material.
 *
 * @param challenge The original challenge issued.
 * @param signatureHex 64-byte signature in hex format.
 * @param publicKey The client's registered public key (Uint8Array or hex string).
 * @returns boolean true if signature is cryptographically valid, false otherwise.
 */
export function verifySchnorrChallenge(
  challenge: SchnorrChallenge | Uint8Array | string,
  signatureHex: string,
  publicKey: Uint8Array | string
): boolean {
  try {
    const pubKeyBytes = typeof publicKey === 'string' ? Buffer.from(publicKey, 'hex') : publicKey;
    const sigBytes = Buffer.from(signatureHex, 'hex');
    const msgBytes = serializeChallenge(challenge);

    if (sigBytes.length !== 64 || pubKeyBytes.length !== 32) {
      return false;
    }

    return schnorr.verify(sigBytes, msgBytes, pubKeyBytes);
  } catch {
    return false;
  }
}
