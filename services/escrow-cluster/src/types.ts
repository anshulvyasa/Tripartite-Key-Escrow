import type { ShamirShare, SchnorrChallenge } from '@trivault/crypto-core';

export type NodeId = 'N1' | 'N2' | 'N3';

export type RecoveryMode = 'RECOVERABLE' | 'STRICT';
export type RecoveryType = 'U_PLUS_E' | 'S_PLUS_E';

export type RecoveryStatus =
  | 'INITIATED'           // Challenge issued & OTP dispatched
  | 'PENDING_DELAY'       // Identity & OTP verified; timelock delay running
  | 'READY_FOR_RELEASE'   // Timelock delay expired without cancellation
  | 'COMPLETED'           // Threshold node shares collected; Escrow Share E reconstructed
  | 'CANCELLED';          // Legitimate user cancelled recovery during delay window

export interface EscrowVaultRecord {
  vaultId: string;
  clientPubKeyHex: string;     // Registered Schnorr public key for challenge-response authentication
  aadhaarNumber: string;       // Registered resident Aadhaar UID for OTP verification
  recoveryMode: RecoveryMode;  // 'RECOVERABLE' or 'STRICT' (disables S+E total loss recovery)
  registeredAt: number;
  lastRotatedAt?: number;
}

export interface RecoverySession {
  requestId: string;
  vaultId: string;
  challenge: SchnorrChallenge;
  aadhaarTxnId: string;
  status: RecoveryStatus;
  recoveryType?: RecoveryType;
  createdAt: number;
  delayExpiresAt?: number;
  cancelledAt?: number;
  cancellationReason?: string;
  contributingNodes?: NodeId[];
}

export interface PolicyEvaluation {
  whatApproved: boolean; // Target vault exists and is actively registered
  howApproved: boolean;  // Factor 1 (Schnorr ZK proof) AND Factor 2 (Aadhaar OTP) valid
  whenApproved: boolean; // Delay timer elapsed without cancellation
  strictModeApproved: boolean; // Confirms recovery type is permitted under vault's recoveryMode
  allowed: boolean;
  reasons: string[];
}

export interface NodeShareRelease {
  nodeId: NodeId;
  vaultId: string;
  subShare: ShamirShare;
  releasedAt: number;
}
