import { verifySchnorrChallenge } from '@trivault/crypto-core';
import type { MockAadhaarService } from '@trivault/mock-aadhaar';
import type { DelayTimer } from './delay-timer.ts';
import type { EscrowVaultRecord, RecoverySession, PolicyEvaluation } from './types.ts';

export interface PolicyEngineConfig {
  requireSchnorr?: boolean;   // default: true
  requireAadhaarOtp?: boolean;// default: true
  defaultDelayMs?: number;    // default: 100ms in dev/test, 24h in production
}

/**
 * What / When / How Policy Engine.
 *
 * Enforces:
 *  1. WHAT: Validates target vault is legitimately registered in the Escrow Cluster.
 *  2. HOW: Validates multi-factor recovery credentials (Factor 1: Schnorr ZK signature + Factor 2: Aadhaar OTP).
 *  3. WHEN: Validates timelock delay has elapsed and request was not cancelled by legitimate user.
 */
export class PolicyEngine {
  private readonly config: Required<PolicyEngineConfig>;
  private readonly aadhaarService: MockAadhaarService;

  constructor(aadhaarService: MockAadhaarService, config: PolicyEngineConfig = {}) {
    this.aadhaarService = aadhaarService;
    this.config = {
      requireSchnorr: config.requireSchnorr ?? true,
      requireAadhaarOtp: config.requireAadhaarOtp ?? true,
      defaultDelayMs: config.defaultDelayMs ?? 100, // 100ms default for fast testing
    };
  }

  get defaultDelayMs(): number {
    return this.config.defaultDelayMs;
  }

  /**
   * Evaluates the "HOW" policy credentials (Schnorr proof + Aadhaar OTP).
   */
  evaluateHow(
    vault: EscrowVaultRecord,
    session: RecoverySession,
    schnorrSignatureHex: string,
    inputOtp: string
  ): { valid: boolean; reasons: string[] } {
    const reasons: string[] = [];

    // Factor 1: Verify Schnorr Challenge-Response Signature
    if (this.config.requireSchnorr) {
      const isSchnorrValid = verifySchnorrChallenge(
        session.challenge,
        schnorrSignatureHex,
        vault.clientPubKeyHex
      );
      if (!isSchnorrValid) {
        reasons.push('Factor 1 Failed: Invalid Schnorr challenge-response signature against registered public key.');
      }
    }

    // Factor 2: Verify Mock Aadhaar OTP
    if (this.config.requireAadhaarOtp) {
      const otpRes = this.aadhaarService.verifyOtp(session.aadhaarTxnId, inputOtp);
      if (!otpRes.success) {
        reasons.push(`Factor 2 Failed: Aadhaar OTP verification failed (${otpRes.error || 'Invalid OTP'}).`);
      } else if (otpRes.aadhaarNumber !== vault.aadhaarNumber) {
        reasons.push('Factor 2 Failed: Aadhaar UID mismatch with registered vault record.');
      }
    }

    // Strict Mode Rule: If vault is in STRICT mode, S+E total loss recovery is strictly forbidden
    if (vault.recoveryMode === 'STRICT' && session.recoveryType === 'S_PLUS_E') {
      reasons.push('Strict Mode Violation: Vault is configured in STRICT mode. Total loss S+E recovery is strictly disabled.');
    }

    return {
      valid: reasons.length === 0,
      reasons,
    };
  }

  /**
   * Evaluates the complete WHAT / WHEN / HOW policy rules for releasing node shares.
   */
  evaluateRelease(
    vault: EscrowVaultRecord | undefined,
    session: RecoverySession,
    delayTimer: DelayTimer
  ): PolicyEvaluation {
    const reasons: string[] = [];

    // 1. WHAT: Target vault exists
    const whatApproved = !!vault;
    if (!whatApproved) {
      reasons.push('WHAT Failed: Vault record not found in Escrow Cluster.');
    }

    // 2. HOW: Previously approved during proof submission
    const howApproved = session.status === 'PENDING_DELAY' || session.status === 'READY_FOR_RELEASE';
    if (!howApproved) {
      reasons.push(`HOW Failed: Credentials not satisfied (current status: ${session.status}).`);
    }

    // 3. WHEN: Delay timer check
    const delayCheck = delayTimer.isElapsed(session.requestId);
    if (delayCheck.cancelled) {
      reasons.push('WHEN Failed: Recovery request was CANCELLED by the user during the delay window.');
    } else if (!delayCheck.elapsed) {
      reasons.push(`WHEN Failed: Timelock delay has not yet expired (${delayCheck.remainingMs}ms remaining).`);
    }
    const whenApproved = delayCheck.elapsed && !delayCheck.cancelled;

    // 4. STRICT MODE: S+E recovery is forbidden if vault is in STRICT mode
    const strictModeApproved = !(vault?.recoveryMode === 'STRICT' && session.recoveryType === 'S_PLUS_E');
    if (!strictModeApproved) {
      reasons.push('Strict Mode Violation: Vault is configured in STRICT mode. Total loss S+E recovery is strictly disabled.');
    }

    const allowed = whatApproved && howApproved && whenApproved && strictModeApproved;

    return {
      whatApproved,
      howApproved,
      whenApproved,
      strictModeApproved,
      allowed,
      reasons,
    };
  }
}
