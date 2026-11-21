import type { EncryptedPayload, WrappedKey, ShamirShare } from '@trivault/crypto-core';

export type RecoveryMode = 'RECOVERABLE' | 'STRICT';

/**
 * Service Provider Vault Record.
 *
 * Invariant: The SP only ever stores:
 *  1. Vault ciphertext (AES-256-GCM)
 *  2. Argon2id salt
 *  3. K_pw-wrapped data key
 *  4. K_rec-wrapped data key
 *  5. Share S (id: 2)
 *  6. Recovery Mode ('RECOVERABLE' or 'STRICT')
 *
 * The SP NEVER receives or stores raw plaintext, raw keys (K_data, K_rec),
 * passwords, or other Shamir shares (U, E).
 */
export interface SPVaultRecord {
  vaultId: string;
  salt: string;                      // Hex-encoded Argon2id salt
  wrappedKeyPw: WrappedKey;          // K_data wrapped under K_pw
  wrappedKeyRec: WrappedKey;         // K_data wrapped under K_rec
  spShare: ShamirShare;              // Share S (id: 2)
  vaultCiphertext: EncryptedPayload; // Encrypted vault payload
  recoveryMode: RecoveryMode;        // 'RECOVERABLE' allows S+E; 'STRICT' disables S+E total loss recovery
  createdAt: number;
  updatedAt: number;
}

export interface SetupVaultRequest {
  vaultId: string;
  salt: string;
  wrappedKeyPw: WrappedKey;
  wrappedKeyRec: WrappedKey;
  spShare: ShamirShare;
  vaultCiphertext: EncryptedPayload;
  recoveryMode?: RecoveryMode;
}

export interface UpdateVaultRequest {
  vaultCiphertext: EncryptedPayload;
}

export interface ResetPasswordRequest {
  salt: string;
  wrappedKeyPw: WrappedKey;
}

export interface RotateRecoveryKeyRequest {
  wrappedKeyRec: WrappedKey;
  spShare: ShamirShare;
  salt?: string;
  wrappedKeyPw?: WrappedKey;
}

export interface LoginDataResponse {
  vaultId: string;
  salt: string;
  wrappedKeyPw: WrappedKey;
  vaultCiphertext: EncryptedPayload;
}

export interface RecoveryDataResponse {
  vaultId: string;
  wrappedKeyRec: WrappedKey;
  spShare: ShamirShare;
  vaultCiphertext?: EncryptedPayload;
  recoveryMode?: RecoveryMode;
}
