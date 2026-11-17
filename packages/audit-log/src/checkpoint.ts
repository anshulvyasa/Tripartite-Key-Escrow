import { signSchnorrChallenge, verifySchnorrChallenge } from '@trivault/crypto-core';
import type { RootCheckpoint, SignedRootCheckpoint } from './types.ts';

/**
 * Canonically serializes a checkpoint into a deterministic byte array for signing and verification.
 */
export function serializeCheckpointForSigning(checkpoint: RootCheckpoint): Uint8Array {
  const canonical = JSON.stringify({
    chainHeadHash: checkpoint.chainHeadHash,
    epoch: checkpoint.epoch,
    lastEventIndex: checkpoint.lastEventIndex,
    merkleRoot: checkpoint.merkleRoot,
    timestamp: checkpoint.timestamp,
  });

  return new TextEncoder().encode(canonical);
}

/**
 * Creates and signs a root checkpoint using a Schnorr private key.
 *
 * @param checkpoint The checkpoint object to sign.
 * @param signerPrivateKey Private key of the auditing authority or coordinator.
 * @param signerPublicKey Public key corresponding to the signer.
 * @returns SignedRootCheckpoint.
 */
export function createSignedCheckpoint(
  checkpoint: RootCheckpoint,
  signerPrivateKey: Uint8Array | string,
  signerPublicKey: Uint8Array | string
): SignedRootCheckpoint {
  const msgBytes = serializeCheckpointForSigning(checkpoint);
  const signature = signSchnorrChallenge(msgBytes, signerPrivateKey);

  const pubKeyHex =
    typeof signerPublicKey === 'string'
      ? signerPublicKey
      : Buffer.from(signerPublicKey).toString('hex');

  return {
    checkpoint,
    signature,
    signerPublicKey: pubKeyHex,
  };
}

/**
 * Verifies the cryptographic signature of a root checkpoint.
 *
 * @param signedCheckpoint The signed checkpoint container.
 * @returns boolean true if the signature is valid, false otherwise.
 */
export function verifySignedCheckpoint(signedCheckpoint: SignedRootCheckpoint): boolean {
  try {
    const msgBytes = serializeCheckpointForSigning(signedCheckpoint.checkpoint);
    return verifySchnorrChallenge(
      msgBytes,
      signedCheckpoint.signature,
      signedCheckpoint.signerPublicKey
    );
  } catch {
    return false;
  }
}
