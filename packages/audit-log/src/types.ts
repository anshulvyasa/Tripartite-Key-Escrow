/**
 * Type Definitions for TriVault Audit Log & Merkle Verification Engine
 */

export interface AuditEvent<T = Record<string, unknown>> {
  index: number;
  timestamp: number;
  action: string;
  actor: string;
  payload: T;
  prevHash: string; // SHA-256 hex of previous event (or genesis hash)
  hash: string;     // SHA-256 hex of this event's canonical fields
}

export interface ChainVerificationResult {
  valid: boolean;
  totalEvents: number;
  brokenIndex?: number;
  reason?: string;
}

export interface MerkleProofSibling {
  position: 'left' | 'right';
  hash: string; // SHA-256 hex
}

export interface MerkleProof {
  leafIndex: number;
  leafHash: string;
  siblings: MerkleProofSibling[];
  merkleRoot: string;
}

export interface RootCheckpoint {
  epoch: number;
  lastEventIndex: number;
  chainHeadHash: string;
  merkleRoot: string;
  timestamp: number;
}

export interface SignedRootCheckpoint {
  checkpoint: RootCheckpoint;
  signature: string;        // 64-byte Schnorr signature in hex
  signerPublicKey: string;  // 32-byte Schnorr public key in hex
}
