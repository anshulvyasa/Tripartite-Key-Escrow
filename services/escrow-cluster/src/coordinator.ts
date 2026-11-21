import crypto from 'node:crypto';
import {
  splitEscrowShare,
  reconstructEscrowShare,
  createSchnorrChallenge,
  generateSchnorrKeyPair,
  type ShamirShare,
  type SchnorrKeyPair,
} from '@trivault/crypto-core';
import { AuditLog, type SignedRootCheckpoint } from '@trivault/audit-log';
import { MockAadhaarService } from '@trivault/mock-aadhaar';

import { EscrowNode } from './escrow-node.ts';
import { PolicyEngine, type PolicyEngineConfig } from './policy-engine.ts';
import { DelayTimer } from './delay-timer.ts';
import type {
  NodeId,
  EscrowVaultRecord,
  RecoverySession,
  RecoveryStatus,
  RecoveryMode,
  RecoveryType,
} from './types.ts';

export interface EscrowCoordinatorConfig {
  policyConfig?: PolicyEngineConfig;
  aadhaarService?: MockAadhaarService;
  coordinatorKeys?: SchnorrKeyPair;
  auditLog?: AuditLog;
}

/**
 * Escrow Cluster Coordinator.
 *
 * Coordinates Nodes N1, N2, N3, What/When/How Policy Engine, Delay Timer, and Audit Log.
 *
 * Invariant:
 * The Coordinator does NOT retain the Escrow Share E in persistent memory.
 * During setup, E is partitioned into {N1, N2, N3} and distributed to the autonomous nodes.
 * During recovery, at least 2 nodes must release sub-shares to recompute E.
 */
export class EscrowCoordinator {
  public readonly nodeN1: EscrowNode;
  public readonly nodeN2: EscrowNode;
  public readonly nodeN3: EscrowNode;

  public readonly policyEngine: PolicyEngine;
  public readonly delayTimer: DelayTimer;
  public readonly aadhaarService: MockAadhaarService;
  public readonly auditLog: AuditLog;
  public readonly coordinatorKeys: SchnorrKeyPair;
  public latestCheckpoint: SignedRootCheckpoint | null = null;

  private readonly vaults: Map<string, EscrowVaultRecord> = new Map();
  private readonly sessions: Map<string, RecoverySession> = new Map();

  constructor(config: EscrowCoordinatorConfig = {}) {
    this.nodeN1 = new EscrowNode('N1');
    this.nodeN2 = new EscrowNode('N2');
    this.nodeN3 = new EscrowNode('N3');

    this.aadhaarService = config.aadhaarService || new MockAadhaarService();
    this.policyEngine = new PolicyEngine(this.aadhaarService, config.policyConfig);
    this.delayTimer = new DelayTimer();
    this.auditLog = config.auditLog || new AuditLog();
    this.coordinatorKeys = config.coordinatorKeys || generateSchnorrKeyPair();
  }

  /**
   * Helper to append an audit event and produce a signed Merkle root checkpoint.
   */
  private logAndCheckpoint(action: string, payload: Record<string, unknown>): SignedRootCheckpoint {
    this.auditLog.append(action, 'escrow-coordinator', payload);
    const checkpoint = this.auditLog.createSignedCheckpoint(
      this.coordinatorKeys.privateKey,
      this.coordinatorKeys.publicKeyHex
    );
    this.latestCheckpoint = checkpoint;
    return checkpoint;
  }

  /**
   * REGISTRATION: Splits Escrow Share E across Nodes N1, N2, N3 and stores recovery policy records.
   */
  registerVault(
    vaultId: string,
    escrowShareE: ShamirShare | Uint8Array,
    clientPubKeyHex: string,
    aadhaarNumber: string,
    recoveryMode: RecoveryMode = 'RECOVERABLE'
  ): SignedRootCheckpoint {
    if (this.vaults.has(vaultId)) {
      throw new Error(`Vault '${vaultId}' is already registered with Escrow Cluster.`);
    }

    // Tier 2: Sub-split E into N1, N2, N3
    const { n1Share, n2Share, n3Share } = splitEscrowShare(escrowShareE);

    // Distribute to isolated nodes
    this.nodeN1.storeSubShare(vaultId, n1Share);
    this.nodeN2.storeSubShare(vaultId, n2Share);
    this.nodeN3.storeSubShare(vaultId, n3Share);

    // Store coordinator metadata (does NOT store E!)
    const record: EscrowVaultRecord = {
      vaultId,
      clientPubKeyHex,
      aadhaarNumber,
      recoveryMode,
      registeredAt: Date.now(),
    };
    this.vaults.set(vaultId, record);

    // Audit log setup event with signed checkpoint
    return this.logAndCheckpoint('ESCROW_VAULT_REGISTERED', {
      vaultId,
      recoveryMode,
      hasClientPubKey: true,
      hasAadhaarNumber: true,
      distributedNodes: ['N1', 'N2', 'N3'],
    });
  }

  /**
   * RECOVERY STEP 1: Initiates recovery, generates Schnorr challenge, and requests Aadhaar OTP.
   * If vault is in STRICT mode and recoveryType is S_PLUS_E, rejects immediately.
   */
  initiateRecovery(
    vaultId: string,
    recoveryType: RecoveryType = 'U_PLUS_E'
  ): {
    requestId: string;
    challenge: ReturnType<typeof createSchnorrChallenge>;
    aadhaarTxnId: string;
    mockOtp?: string;
  } {
    const vault = this.vaults.get(vaultId);
    if (!vault) {
      throw new Error(`Vault '${vaultId}' not found in Escrow Cluster.`);
    }

    if (vault.recoveryMode === 'STRICT' && recoveryType === 'S_PLUS_E') {
      this.auditLog.append('STRICT_MODE_VIOLATION_BLOCKED', 'escrow-coordinator', {
        vaultId,
        recoveryType,
        reason: 'Attempted S+E total loss recovery on a vault in STRICT mode',
      });
      throw new Error(
        `Strict Mode Violation: Vault '${vaultId}' is configured in STRICT mode. Total loss S+E recovery is strictly disabled.`
      );
    }

    const requestId = crypto.randomUUID();
    const challenge = createSchnorrChallenge(`recovery-${vaultId}`);

    // Trigger Mock Aadhaar OTP
    const otpResult = this.aadhaarService.generateOtp(vault.aadhaarNumber);
    if (!otpResult.success) {
      throw new Error(`Failed to generate Aadhaar OTP: ${otpResult.error}`);
    }

    const session: RecoverySession = {
      requestId,
      vaultId,
      challenge,
      aadhaarTxnId: otpResult.txnId,
      recoveryType,
      status: 'INITIATED',
      createdAt: Date.now(),
    };

    this.sessions.set(requestId, session);

    this.auditLog.append('RECOVERY_REQUESTED', 'escrow-coordinator', { requestId, vaultId, recoveryType });
    this.auditLog.append('CHALLENGE_ISSUED', 'escrow-coordinator', {
      requestId,
      nonce: challenge.nonce,
      timestamp: challenge.timestamp,
    });

    return {
      requestId,
      challenge,
      aadhaarTxnId: otpResult.txnId,
      mockOtp: otpResult.mockOtp,
    };
  }

  /**
   * KEY ROTATION (Algorithm 2 Steps 8-9 & Algorithm 4 Step 5):
   * Replaces old Escrow Share E with fresh E' across Nodes N1, N2, N3.
   * Revokes previous node sub-shares, updates registered client public key if provided,
   * and records signed Merkle checkpoints.
   */
  rotateVaultEscrow(
    vaultId: string,
    newEscrowShareE: ShamirShare | Uint8Array,
    newClientPubKeyHex?: string
  ): { success: boolean; vaultId: string; checkpoint: SignedRootCheckpoint } {
    const vault = this.vaults.get(vaultId);
    if (!vault) {
      throw new Error(`Vault '${vaultId}' not found in Escrow Cluster.`);
    }

    // Sub-split new E' across N1, N2, N3
    const { n1Share, n2Share, n3Share } = splitEscrowShare(newEscrowShareE);

    // Revoke old sub-shares and store fresh sub-shares on isolated nodes
    this.nodeN1.revokeAndReplaceSubShare(vaultId, n1Share);
    this.nodeN2.revokeAndReplaceSubShare(vaultId, n2Share);
    this.nodeN3.revokeAndReplaceSubShare(vaultId, n3Share);

    this.auditLog.append('NODE_SHARES_REVOKED', 'escrow-coordinator', {
      vaultId,
      revokedNodes: ['N1', 'N2', 'N3'],
      timestamp: Date.now(),
    });

    if (newClientPubKeyHex) {
      vault.clientPubKeyHex = newClientPubKeyHex;
    }
    vault.lastRotatedAt = Date.now();

    const checkpoint = this.logAndCheckpoint('ESCROW_KEY_ROTATED', {
      vaultId,
      hasNewClientPubKey: !!newClientPubKeyHex,
      rotatedAt: vault.lastRotatedAt,
      distributedNodes: ['N1', 'N2', 'N3'],
    });

    return {
      success: true,
      vaultId,
      checkpoint,
    };
  }

  /**
   * RECOVERY STEP 2: Submits Schnorr signature and Aadhaar OTP; evaluates policy and starts delay timer.
   */
  submitRecoveryProof(
    requestId: string,
    schnorrSignatureHex: string,
    inputOtp: string,
    customDelayMs?: number
  ): {
    status: RecoveryStatus;
    delayExpiresAt: number;
    remainingMs: number;
    checkpoint: SignedRootCheckpoint;
  } {
    const session = this.sessions.get(requestId);
    if (!session) {
      throw new Error(`Recovery session '${requestId}' not found.`);
    }
    if (session.status !== 'INITIATED') {
      throw new Error(`Recovery session is in '${session.status}' state, expected 'INITIATED'.`);
    }

    const vault = this.vaults.get(session.vaultId)!;

    // Evaluate "HOW" policy rules
    const howResult = this.policyEngine.evaluateHow(
      vault,
      session,
      schnorrSignatureHex,
      inputOtp
    );

    if (!howResult.valid) {
      this.auditLog.append('POLICY_CHECK_FAILED', 'escrow-coordinator', {
        requestId,
        reasons: howResult.reasons,
      });
      throw new Error(`Recovery Policy Verification Failed: ${howResult.reasons.join(' | ')}`);
    }

    // Credentials verified!
    this.auditLog.append('CHALLENGE_VERIFIED', 'escrow-coordinator', { requestId });
    this.auditLog.append('AADHAAR_OTP_VERIFIED', 'escrow-coordinator', { requestId });
    this.auditLog.append('POLICY_CHECK_PASSED', 'escrow-coordinator', { requestId });

    // Start timelock delay window
    const delayDuration = customDelayMs ?? this.policyEngine.defaultDelayMs;
    const { expiresAt } = this.delayTimer.startTimer(requestId, session.vaultId, delayDuration);

    session.status = 'PENDING_DELAY';
    session.delayExpiresAt = expiresAt;

    const checkpoint = this.logAndCheckpoint('DELAY_TIMER_STARTED', {
      requestId,
      vaultId: session.vaultId,
      delayDurationMs: delayDuration,
      delayExpiresAt: expiresAt,
    });

    return {
      status: 'PENDING_DELAY',
      delayExpiresAt: expiresAt,
      remainingMs: Math.max(0, expiresAt - Date.now()),
      checkpoint,
    };
  }

  /**
   * CANCELLATION: Allows legitimate user to abort unauthorized recovery attempt during delay window.
   */
  cancelRecovery(requestId: string, reason: string): SignedRootCheckpoint {
    const session = this.sessions.get(requestId);
    if (!session) {
      throw new Error(`Recovery session '${requestId}' not found.`);
    }

    if (session.status === 'COMPLETED') {
      throw new Error('Cannot cancel recovery: shares have already been released.');
    }
    if (session.status === 'CANCELLED') {
      throw new Error('Recovery session is already cancelled.');
    }

    this.delayTimer.cancelTimer(requestId, reason);

    session.status = 'CANCELLED';
    session.cancelledAt = Date.now();
    session.cancellationReason = reason;

    return this.logAndCheckpoint('RECOVERY_CANCELLED', {
      requestId,
      vaultId: session.vaultId,
      reason,
      cancelledAt: session.cancelledAt,
    });
  }

  /**
   * RECOVERY STEP 3: Complete recovery after delay timer expires.
   * Collects sub-shares from at least 2 nodes, reconstructs Escrow Share E, and checkpoints the event.
   */
  completeRecovery(
    requestId: string,
    nodePair: [NodeId, NodeId] = ['N1', 'N2']
  ): {
    success: boolean;
    escrowShare: ShamirShare;
    contributingNodes: NodeId[];
    checkpoint: SignedRootCheckpoint;
  } {
    const session = this.sessions.get(requestId);
    if (!session) {
      throw new Error(`Recovery session '${requestId}' not found.`);
    }

    const vault = this.vaults.get(session.vaultId);

    // Evaluate complete WHAT / WHEN / HOW policy rules
    const evaluation = this.policyEngine.evaluateRelease(vault, session, this.delayTimer);
    if (!evaluation.allowed) {
      throw new Error(`Cannot release escrow shares: ${evaluation.reasons.join(' | ')}`);
    }

    const authToken = crypto.randomBytes(32).toString('hex');
    const subShares: ShamirShare[] = [];
    const contributingNodes: NodeId[] = [];

    // Collect from chosen pair of nodes
    for (const nodeId of nodePair) {
      const node = nodeId === 'N1' ? this.nodeN1 : nodeId === 'N2' ? this.nodeN2 : this.nodeN3;
      const release = node.releaseSubShare(session.vaultId, authToken);
      subShares.push(release.subShare);
      contributingNodes.push(nodeId);

      this.auditLog.append('NODE_SHARE_RELEASED', `escrow-node-${nodeId.toLowerCase()}`, {
        requestId,
        nodeId,
        subShareId: release.subShare.id,
      });
    }

    // Reconstruct Escrow Share E (id: 3) from the 2 node shares
    const reconstructedE = reconstructEscrowShare(subShares);

    session.status = 'COMPLETED';
    session.contributingNodes = contributingNodes;

    const checkpoint = this.logAndCheckpoint('ESCROW_SHARE_RECONSTRUCTED', {
      requestId,
      vaultId: session.vaultId,
      contributingNodes,
      reconstructedShareId: reconstructedE.id,
    });

    return {
      success: true,
      escrowShare: reconstructedE,
      contributingNodes,
      checkpoint,
    };
  }

  /**
   * Returns session details.
   */
  getSession(requestId: string): RecoverySession | undefined {
    return this.sessions.get(requestId);
  }

  /**
   * Cleans up background timer handles.
   */
  shutdown(): void {
    this.delayTimer.clear();
  }
}
