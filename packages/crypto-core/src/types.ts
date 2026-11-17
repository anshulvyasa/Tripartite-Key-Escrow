/**
 * Cryptographic Core Type Definitions for TriVault
 */

export interface EncryptedPayload {
  ciphertext: string; // Base64 encoded ciphertext
  iv: string;         // Base64 encoded 96-bit IV
  tag: string;        // Base64 encoded 128-bit authentication tag
  aad?: string;       // Base64 encoded additional authenticated data (optional)
}

export interface WrappedKey {
  wrappedKey: string; // Base64 encoded wrapped key ciphertext
  iv: string;         // Base64 encoded 96-bit IV
  tag: string;        // Base64 encoded 128-bit authentication tag
}

export interface Argon2Params {
  timeCost?: number;      // Iterations (t)
  memoryCostKiB?: number; // Memory cost in KiB (m)
  parallelism?: number;   // Parallelism lanes (p)
  keyLength?: number;     // Output key length (default 32 bytes)
}

export interface ShamirShare {
  id: number;   // X-coordinate (1-based index)
  data: string; // Hex-encoded share payload
}

export interface TopLevelShares {
  userShare: ShamirShare;      // Share U (id: 1)
  spShare: ShamirShare;        // Share S (id: 2)
  escrowShare: ShamirShare;    // Share E (id: 3)
}

export interface EscrowSubShares {
  n1Share: ShamirShare; // Share N1 (id: 1)
  n2Share: ShamirShare; // Share N2 (id: 2)
  n3Share: ShamirShare; // Share N3 (id: 3)
}

export interface SchnorrKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  privateKeyHex: string;
  publicKeyHex: string;
}

export interface SchnorrChallenge {
  nonce: string;     // Hex-encoded random challenge nonce
  timestamp: number; // Challenge generation timestamp in ms
  context?: string;  // Optional domain separation or user identifier context
}
