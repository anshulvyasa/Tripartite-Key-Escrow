import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateDataKey,
  splitRecoveryKey,
  generateSchnorrKeyPair,
  signSchnorrChallenge,
  reconstructRecoveryKey,
  wrapKey,
  unwrapKey,
  encryptVault,
  decryptVault,
} from '@trivault/crypto-core';
import { verifySignedCheckpoint } from '@trivault/audit-log';
import { MockAadhaarService } from '@trivault/mock-aadhaar';
import { EscrowCoordinator } from '../src/coordinator.ts';

describe('Escrow Cluster, Policy Engine, Delay Timer & Audit Log Integration', () => {
  let coordinator: EscrowCoordinator;
  let aadhaarService: MockAadhaarService;

  beforeEach(() => {
    aadhaarService = new MockAadhaarService();
    coordinator = new EscrowCoordinator({
      aadhaarService,
      policyConfig: {
        defaultDelayMs: 60, // 60ms delay for fast automated testing
      },
    });
  });

  afterEach(() => {
    coordinator.shutdown();
  });

  it('PROVE: Full Escrow Registration, Multi-Factor Challenge, Timelock Delay, and 2-of-3 Node Share Reconstruction', async () => {
    // =========================================================================
    // 1. Vault Setup & Tier 1 Split
    // =========================================================================
    const vaultId = 'escrow-vault-test-01';
    const aadhaarUid = '123456789012'; // Alice's UID
    const clientKeys = generateSchnorrKeyPair();

    const kData = generateDataKey();
    const kRec = generateDataKey();

    // Wrap K_data under K_rec
    const wrappedKeyRec = wrapKey(kData, kRec);
    const vaultSecret = 'Disaster Recovery Vault Content: Seed Phrases and Encrypted Keys';
    const vaultCiphertext = encryptVault(vaultSecret, kData);

    // Tier 1 Shamir split into U, S, E
    const { userShare, spShare, escrowShare } = splitRecoveryKey(kRec);

    // =========================================================================
    // 2. Escrow Registration (Tier 2 Sub-Split to N1, N2, N3)
    // =========================================================================
    const registrationCheckpoint = coordinator.registerVault(
      vaultId,
      escrowShare,
      clientKeys.publicKeyHex,
      aadhaarUid
    );

    assert.ok(registrationCheckpoint.signature);
    assert.strictEqual(verifySignedCheckpoint(registrationCheckpoint), true);

    // Verify Nodes N1, N2, N3 hold only their respective sub-shares
    assert.strictEqual(coordinator.nodeN1.hasSubShare(vaultId), true);
    assert.strictEqual(coordinator.nodeN2.hasSubShare(vaultId), true);
    assert.strictEqual(coordinator.nodeN3.hasSubShare(vaultId), true);

    // =========================================================================
    // 3. Recovery Request Initiation (Challenge & OTP Dispatch)
    // =========================================================================
    const initResult = coordinator.initiateRecovery(vaultId);
    assert.ok(initResult.requestId);
    assert.ok(initResult.challenge.nonce);
    assert.ok(initResult.mockOtp, 'Mock Aadhaar OTP must be generated');

    const requestId = initResult.requestId;

    // =========================================================================
    // 4. Client Sign Challenge & Submit Multi-Factor Proof (Factor 1 + Factor 2)
    // =========================================================================
    const clientSignature = signSchnorrChallenge(initResult.challenge, clientKeys.privateKey);

    // Submit valid proof (Schnorr signature + OTP)
    const proofResult = coordinator.submitRecoveryProof(
      requestId,
      clientSignature,
      initResult.mockOtp!
    );

    assert.strictEqual(proofResult.status, 'PENDING_DELAY');
    assert.ok(proofResult.delayExpiresAt > Date.now());
    assert.strictEqual(verifySignedCheckpoint(proofResult.checkpoint), true);

    // =========================================================================
    // 5. Premature Attempt to Complete Recovery Must Fail Timelock Check
    // =========================================================================
    assert.throws(
      () => coordinator.completeRecovery(requestId, ['N1', 'N2']),
      /WHEN Failed: Timelock delay has not yet expired/,
      'Premature release before timelock expiry must be rejected by Policy Engine'
    );

    // =========================================================================
    // 6. Wait for Timelock Delay to Elapse
    // =========================================================================
    await new Promise((resolve) => setTimeout(resolve, 80));

    // =========================================================================
    // 7. Complete Recovery: Collect Sub-Shares from N1 + N2 -> Reconstruct E
    // =========================================================================
    const recoveryResult = coordinator.completeRecovery(requestId, ['N1', 'N2']);
    assert.strictEqual(recoveryResult.success, true);
    assert.deepStrictEqual(recoveryResult.contributingNodes, ['N1', 'N2']);
    assert.strictEqual(recoveryResult.escrowShare.id, 3);
    assert.strictEqual(
      recoveryResult.escrowShare.data,
      escrowShare.data,
      'Reconstructed Escrow Share E must mathematically match original Escrow Share'
    );
    assert.strictEqual(verifySignedCheckpoint(recoveryResult.checkpoint), true);

    // =========================================================================
    // 8. Reconstruct Recovery Key (K_rec) and Decrypt Vault
    // =========================================================================
    // Path A: Reconstruct K_rec using User Share U + Reconstructed E
    const recoveredKRec_User = reconstructRecoveryKey([userShare, recoveryResult.escrowShare]);
    assert.deepStrictEqual(recoveredKRec_User, kRec);

    const unwrappedKData_User = unwrapKey(wrappedKeyRec, recoveredKRec_User);
    assert.deepStrictEqual(unwrappedKData_User, kData);

    const decryptedVault_User = decryptVault(vaultCiphertext, unwrappedKData_User);
    assert.strictEqual(new TextDecoder().decode(decryptedVault_User), vaultSecret);

    // Path B: Reconstruct K_rec using SP Share S + Reconstructed E
    const recoveredKRec_SP = reconstructRecoveryKey([spShare, recoveryResult.escrowShare]);
    assert.deepStrictEqual(recoveredKRec_SP, kRec);

    const unwrappedKData_SP = unwrapKey(wrappedKeyRec, recoveredKRec_SP);
    assert.deepStrictEqual(unwrappedKData_SP, kData);

    const decryptedVault_SP = decryptVault(vaultCiphertext, unwrappedKData_SP);
    assert.strictEqual(new TextDecoder().decode(decryptedVault_SP), vaultSecret);

    // =========================================================================
    // 9. Verify Complete Audit Log Chain & Signed Merkle Checkpoint
    // =========================================================================
    const chainVerification = coordinator.auditLog.verifyChainIntegrity();
    assert.strictEqual(chainVerification.valid, true);
    assert.ok(chainVerification.totalEvents >= 8);

    const events = coordinator.auditLog.getEvents();
    const actionNames = events.map((e) => e.action);
    assert.ok(actionNames.includes('ESCROW_VAULT_REGISTERED'));
    assert.ok(actionNames.includes('RECOVERY_REQUESTED'));
    assert.ok(actionNames.includes('CHALLENGE_ISSUED'));
    assert.ok(actionNames.includes('CHALLENGE_VERIFIED'));
    assert.ok(actionNames.includes('AADHAAR_OTP_VERIFIED'));
    assert.ok(actionNames.includes('POLICY_CHECK_PASSED'));
    assert.ok(actionNames.includes('DELAY_TIMER_STARTED'));
    assert.ok(actionNames.includes('NODE_SHARE_RELEASED'));
    assert.ok(actionNames.includes('ESCROW_SHARE_RECONSTRUCTED'));
  });

  it('PROVE: Legitimate user can cancel unauthorized recovery during delay window', async () => {
    const vaultId = 'escrow-cancellation-test';
    const aadhaarUid = '987654321098'; // Bob's UID
    const clientKeys = generateSchnorrKeyPair();
    const kRec = generateDataKey();
    const { escrowShare } = splitRecoveryKey(kRec);

    coordinator.registerVault(vaultId, escrowShare, clientKeys.publicKeyHex, aadhaarUid);

    // 1. Recovery is initiated
    const initResult = coordinator.initiateRecovery(vaultId);
    const clientSignature = signSchnorrChallenge(initResult.challenge, clientKeys.privateKey);

    // 2. Proof submitted with 500ms delay window
    coordinator.submitRecoveryProof(initResult.requestId, clientSignature, initResult.mockOtp!, 500);

    // 3. User receives alert and cancels recovery
    const cancelCheckpoint = coordinator.cancelRecovery(
      initResult.requestId,
      'User was not requesting recovery (suspicious access)'
    );
    assert.ok(cancelCheckpoint.signature);
    assert.strictEqual(verifySignedCheckpoint(cancelCheckpoint), true);

    const session = coordinator.getSession(initResult.requestId);
    assert.strictEqual(session?.status, 'CANCELLED');

    // 4. Attempting to complete recovery even after delay must be REJECTED
    await new Promise((resolve) => setTimeout(resolve, 60));
    assert.throws(
      () => coordinator.completeRecovery(initResult.requestId, ['N1', 'N2']),
      /WHEN Failed: Recovery request was CANCELLED by the user/,
      'Cancelled recovery must never release shares'
    );
  });

  it('PROVE: Policy Engine rejects invalid Schnorr signatures or incorrect Aadhaar OTP', () => {
    const vaultId = 'escrow-rejection-test';
    const aadhaarUid = '123456789012';
    const legitimateKeys = generateSchnorrKeyPair();
    const impostorKeys = generateSchnorrKeyPair();
    const kRec = generateDataKey();
    const { escrowShare } = splitRecoveryKey(kRec);

    coordinator.registerVault(vaultId, escrowShare, legitimateKeys.publicKeyHex, aadhaarUid);

    const initResult = coordinator.initiateRecovery(vaultId);

    // Attack 1: Impostor signs challenge
    const impostorSignature = signSchnorrChallenge(initResult.challenge, impostorKeys.privateKey);
    assert.throws(
      () => coordinator.submitRecoveryProof(initResult.requestId, impostorSignature, initResult.mockOtp!),
      /Factor 1 Failed: Invalid Schnorr challenge-response signature/,
      'Unauthorized Schnorr signature must fail policy check'
    );

    // Attack 2: Correct signature but wrong Aadhaar OTP
    const legitimateSignature = signSchnorrChallenge(initResult.challenge, legitimateKeys.privateKey);
    assert.throws(
      () => coordinator.submitRecoveryProof(initResult.requestId, legitimateSignature, '000000'),
      /Factor 2 Failed: Aadhaar OTP verification failed/,
      'Incorrect Aadhaar OTP must fail policy check'
    );
  });
});
