import type { ShamirShare, SchnorrKeyPair, Argon2Params } from '@trivault/crypto-core';

export type RecoveryMode = 'RECOVERABLE' | 'STRICT';

export interface SetupVaultOptions {
  recoveryMode?: RecoveryMode;
}

export interface VaultSetupResult {
  vaultId: string;
  userShare: ShamirShare;       // Share U (id: 1) held locally by client
  escrowShare: ShamirShare;     // Share E (id: 3) to be sub-split across escrow nodes
  schnorrKeys: SchnorrKeyPair;  // Client Schnorr identity (privkey retained locally)
  salt: string;                 // Hex salt used for K_pw derivation
  dataKey: Uint8Array;          // Active session K_data
  recoveryMode: RecoveryMode;   // 'RECOVERABLE' or 'STRICT'
}

export interface VaultLoginResult {
  vaultId: string;
  dataKey: Uint8Array;          // Locally unwrapped K_data
  plaintext: string;            // Decrypted vault payload as string
  plaintextBytes: Uint8Array;   // Raw decrypted bytes for binary payloads
}

export interface ForgotPasswordResult {
  vaultId: string;
  dataKey: Uint8Array;
  plaintext: string;
  plaintextBytes: Uint8Array;
  salt: string;
  passwordReset: boolean;
}

export interface Algorithm2RecoveryResult {
  vaultId: string;
  dataKey: Uint8Array;
  plaintext: string;
  plaintextBytes: Uint8Array;
  sharesUsed: {
    share1Id: number; // User Share U (id: 1)
    share2Id: number; // Escrow Share E (id: 3)
  };
  // Steps 8 & 9 Key Rotation outputs
  rotated: boolean;
  newUserShare: ShamirShare; // Fresh U' (id: 1)
  newEscrowShare: ShamirShare; // Fresh E' (id: 3)
  newSchnorrKeys?: SchnorrKeyPair;
  escrowCheckpoint?: any;
}

export interface Algorithm4RecoveryResult {
  vaultId: string;
  dataKey: Uint8Array;
  plaintext: string;
  plaintextBytes: Uint8Array;
  sharesUsed: {
    share1Id: number; // SP Share S (id: 2)
    share2Id: number; // Escrow Share E (id: 3)
  };
  // Step 5 Key Rotation & Device Reset outputs
  rotated: boolean;
  newUserShare: ShamirShare; // Fresh U' (id: 1)
  newEscrowShare: ShamirShare; // Fresh E' (id: 3)
  newSchnorrKeys: SchnorrKeyPair;
  newSalt?: string;
  passwordReset: boolean;
  escrowCheckpoint?: any;
}

export interface EscrowRegistrationResult {
  success: boolean;
  vaultId: string;
  checkpoint: any;
}

export interface RecoveryInitiationResult {
  requestId: string;
  challenge: {
    nonce: string;
    message: string;
    timestamp: number;
  };
  aadhaarTxnId: string;
  mockOtp?: string;
}

export interface RecoveryProofResult {
  status: string;
  delayExpiresAt: number;
  remainingMs: number;
  checkpoint: any;
}

export interface RecoveryCompleteResult {
  success: boolean;
  escrowShare: ShamirShare;
  contributingNodes: string[];
  checkpoint: any;
}

export interface VaultRecoveryResult {
  vaultId: string;
  dataKey: Uint8Array;
  kRec: Uint8Array;
  plaintext: string;
  plaintextBytes: Uint8Array;
  sharesUsed: {
    share1Id: number;
    share2Id: number;
  };
}

export interface VaultClientConfig {
  spUrl: string;                // URL (or pipe path) to Service Provider
  escrowUrl?: string;           // Optional URL (or pipe path) to Escrow Cluster Coordinator
  enableMTLS?: boolean;
  certsDir?: string;
  argon2Params?: Argon2Params;  // Argon2id parameters (customizable for fast testing)
}
