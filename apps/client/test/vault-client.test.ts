import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { VaultClient } from '../src/vault-client.ts';
import {
  splitEscrowShare,
  reconstructFromHierarchicalShares,
  reconstructRecoveryKey,
  generateSchnorrKeyPair,
  signSchnorrChallenge,
  unwrapKey,
  decryptVault,
  FAST_TEST_ARGON2_PARAMS,
} from '@trivault/crypto-core';
import { ServiceProviderServer } from '../../../services/service-provider/src/server.ts';
import { VaultStorage } from '../../../services/service-provider/src/storage.ts';
import { EscrowServer } from '../../../services/escrow-cluster/src/server.ts';
import { EscrowCoordinator } from '../../../services/escrow-cluster/src/coordinator.ts';
import { MockAadhaarService } from '../../../services/mock-aadhaar/src/mock-aadhaar.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const certsDir = path.resolve(__dirname, '../../../certs');

describe('@trivault/client - Client Workflow & Hierarchical Recovery Correlation', () => {
  let spServer: ServiceProviderServer;
  let spStorage: VaultStorage;
  let escrowServer: EscrowServer;
  let escrowCoordinator: EscrowCoordinator;
  let aadhaarService: MockAadhaarService;
  let client: VaultClient;

  const spPipe = `\\\\.\\pipe\\trivault-client-sp-${Date.now()}`;
  const escrowPipe = `\\\\.\\pipe\\trivault-client-escrow-${Date.now()}`;

  before(async () => {
    // 1. Service Provider Setup
    spStorage = new VaultStorage();
    spServer = new ServiceProviderServer({
      storage: spStorage,
      certsDir,
      enableMTLS: true,
    });
    await spServer.start(spPipe);

    // 2. Escrow Cluster Setup with Mock Aadhaar
    aadhaarService = new MockAadhaarService();
    escrowCoordinator = new EscrowCoordinator({
      aadhaarService,
      policyConfig: { defaultDelayMs: 20 },
    });
    escrowServer = new EscrowServer({
      coordinator: escrowCoordinator,
      certsDir,
      enableMTLS: true,
    });
    await escrowServer.start(escrowPipe);

    // 3. Vault Client Setup with both SP and Escrow URLs
    client = new VaultClient({
      spUrl: spPipe,
      escrowUrl: escrowPipe,
      certsDir,
      enableMTLS: true,
      argon2Params: FAST_TEST_ARGON2_PARAMS,
    });
  });

  after(async () => {
    await client;
    await spServer.stop();
    await escrowServer.stop();
  });

  it('PROVE: Client setup creates two-tier Shamir shares and allows full disaster recovery with Escrow sub-shares', async () => {
    const vaultId = 'client-workflow-vault-101';
    const password = 'ClientUltraSecurePassword#2026';
    const secretMessage = 'Confidential TriVault Master Configuration & API Keys';

    // 1. Client creates vault via Algorithm 1
    const setupResult = await client.setupVault(vaultId, password, secretMessage);
    assert.strictEqual(setupResult.vaultId, vaultId);

    // 2. Daily login via Algorithm 3
    const loginResult = await client.login(vaultId, password);
    assert.strictEqual(loginResult.plaintext, secretMessage);
    assert.deepStrictEqual(loginResult.plaintextBytes, new TextEncoder().encode(secretMessage));

    // 3. Obtain Recovery Metadata from SP (wrappedKeyRec, Share S)
    const spRecoveryData = spStorage.getRecoveryData(vaultId);
    const { wrappedKeyRec, spShare } = spRecoveryData;

    // 4. Client's Escrow Share (E, id: 3) is sub-split across 3 Escrow Nodes (N1, N2, N3)
    const { n1Share, n2Share, n3Share } = splitEscrowShare(setupResult.escrowShare);
    assert.strictEqual(n1Share.id, 1);
    assert.strictEqual(n2Share.id, 2);
    assert.strictEqual(n3Share.id, 3);

    // 5. Test Disaster Recovery Path 1: User Share (U) + 2 Escrow Nodes (N1, N2)
    const recoveredKRec_Path1 = reconstructFromHierarchicalShares(setupResult.userShare, [n1Share, n2Share]);
    const unwrappedKData_Path1 = unwrapKey(wrappedKeyRec, recoveredKRec_Path1);
    assert.deepStrictEqual(unwrappedKData_Path1, setupResult.dataKey);

    const decryptedVault_Path1 = decryptVault(
      spStorage.getLoginData(vaultId).vaultCiphertext,
      unwrappedKData_Path1
    );
    assert.strictEqual(new TextDecoder().decode(decryptedVault_Path1), secretMessage);

    // 6. Test Disaster Recovery Path 2: Service Provider Share (S) + 2 Escrow Nodes (N2, N3)
    const recoveredKRec_Path2 = reconstructFromHierarchicalShares(spShare, [n2Share, n3Share]);
    const unwrappedKData_Path2 = unwrapKey(wrappedKeyRec, recoveredKRec_Path2);
    assert.deepStrictEqual(unwrappedKData_Path2, setupResult.dataKey);

    const decryptedVault_Path2 = decryptVault(
      spStorage.getLoginData(vaultId).vaultCiphertext,
      unwrappedKData_Path2
    );
    assert.strictEqual(new TextDecoder().decode(decryptedVault_Path2), secretMessage);

    // 7. Test Insufficient Escrow Nodes: User Share (U) + only 1 Escrow Node (N1) fails
    assert.throws(
      () => reconstructFromHierarchicalShares(setupResult.userShare, [n1Share]),
      /Insufficient shares/,
      '1 Escrow node share must fail to reconstruct Escrow Share E'
    );
  });

  it('PROVE: End-to-end Escrow Recovery with live EscrowServer, SP, and mTLS', async () => {
    const vaultId = 'e2e-escrow-vault-202';
    const password = 'CorrectPassword#2026';
    const secretMessage = 'Secret E2E Payload: BTC Seed Phrase & SSH Private Keys';
    const aadhaarNumber = '555566667777';

    // 1. Register resident in Mock Aadhaar
    aadhaarService.registerProfile({
      aadhaarNumber,
      phoneNumber: '+91-9999999999',
      name: 'Alice Resident',
    });

    // 2. Setup vault on Service Provider (Algorithm 1)
    const setupResult = await client.setupVault(vaultId, password, secretMessage);
    assert.strictEqual(setupResult.vaultId, vaultId);

    // 3. Register Escrow Share E with Escrow Cluster
    const regResult = await client.registerWithEscrow(
      vaultId,
      setupResult.escrowShare,
      setupResult.schnorrKeys.publicKeyHex,
      aadhaarNumber
    );
    assert.strictEqual(regResult.success, true);
    assert.ok(regResult.checkpoint);

    // 4. Simulate Disaster: User forgot their password
    // Normal login with wrong password fails
    await assert.rejects(
      () => client.login(vaultId, 'WrongForgottenPassword'),
      /Vault decryption authentication failed|unable to authenticate/
    );

    // 5. Initiate Escrow Recovery
    const init = await client.initiateEscrowRecovery(vaultId);
    assert.ok(init.requestId);
    assert.ok(init.challenge);
    assert.ok(init.mockOtp);

    // 6. Complete End-to-End Recovery via recoverVaultWithEscrow
    const recoveryResult = await client.recoverVaultWithEscrow({
      vaultId,
      initSession: init,
      clientPrivateKey: setupResult.schnorrKeys.privateKey,
      otp: init.mockOtp,
      customDelayMs: 20,
    });

    assert.strictEqual(recoveryResult.vaultId, vaultId);
    assert.strictEqual(recoveryResult.plaintext, secretMessage);
    assert.deepStrictEqual(recoveryResult.dataKey, setupResult.dataKey);
    assert.strictEqual(recoveryResult.sharesUsed.share1Id, 2, 'SP Share S (id: 2)');
    assert.strictEqual(recoveryResult.sharesUsed.share2Id, 3, 'Escrow Share E (id: 3)');
  });

  it('PROVE: Timelock cancellation prevents share release during delay window', async () => {
    const vaultId = 'timelock-cancel-vault-303';
    const password = 'Password#303';
    const secretMessage = 'Secret to protect from unauthorized recovery';
    const aadhaarNumber = '888899990000';

    aadhaarService.registerProfile({
      aadhaarNumber,
      phoneNumber: '+91-8888888888',
      name: 'Bob Resident',
    });

    const setupResult = await client.setupVault(vaultId, password, secretMessage);
    await client.registerWithEscrow(
      vaultId,
      setupResult.escrowShare,
      setupResult.schnorrKeys.publicKeyHex,
      aadhaarNumber
    );

    // 1. Attacker initiates recovery
    const init = await client.initiateEscrowRecovery(vaultId);

    // 2. Proof submitted with 500ms delay
    const sig = signSchnorrChallenge(init.challenge, setupResult.schnorrKeys.privateKey);
    const proofResult = await client.submitEscrowRecoveryProof(
      init.requestId,
      sig,
      init.mockOtp!,
      500
    );
    assert.strictEqual(proofResult.status, 'PENDING_DELAY');

    // 3. Legitimate user notices alert and cancels recovery
    const cancelResult = await client.cancelEscrowRecovery(
      init.requestId,
      'Unauthorized recovery attempt detected by user'
    );
    assert.strictEqual(cancelResult.success, true);
    assert.strictEqual(cancelResult.status, 'CANCELLED');

    // 4. Attempting to complete recovery must fail
    await assert.rejects(
      () => client.completeEscrowRecovery(init.requestId),
      /CANCELLED by the user|Recovery request was CANCELLED/
    );
  });

  it('PROVE: Policy Engine rejects unauthorized recovery proofs (wrong Schnorr key or wrong OTP)', async () => {
    const vaultId = 'policy-rejection-vault-404';
    const password = 'Password#404';
    const aadhaarNumber = '111122223333';

    aadhaarService.registerProfile({
      aadhaarNumber,
      phoneNumber: '+91-7777777777',
      name: 'Carol Resident',
    });

    const setupResult = await client.setupVault(vaultId, password, 'Some payload');
    await client.registerWithEscrow(
      vaultId,
      setupResult.escrowShare,
      setupResult.schnorrKeys.publicKeyHex,
      aadhaarNumber
    );

    // 1. Initiate recovery
    const init = await client.initiateEscrowRecovery(vaultId);

    // 2. Rogue private key attempt
    const rogueKeys = generateSchnorrKeyPair();
    const badSig = signSchnorrChallenge(init.challenge, rogueKeys.privateKey);

    await assert.rejects(
      () => client.submitEscrowRecoveryProof(init.requestId, badSig, init.mockOtp!),
      /Factor 1 Failed.*Invalid Schnorr challenge-response signature/
    );

    // 3. Initiate fresh recovery session for OTP test
    const init2 = await client.initiateEscrowRecovery(vaultId);
    const goodSig = signSchnorrChallenge(init2.challenge, setupResult.schnorrKeys.privateKey);

    await assert.rejects(
      () => client.submitEscrowRecoveryProof(init2.requestId, goodSig, '999999'),
      /Factor 2 Failed: Aadhaar OTP verification failed/
    );
  });

  it('PROVE: Forgot Password workflow (U + S) recovers vault, resets password, and updates SP without leaking keys', async () => {
    const vaultId = 'forgot-pw-vault-505';
    const oldPassword = 'OldInitialPassword#2026';
    const newPassword = 'BrandNewResetPassword#2026!';
    const secretContent = 'Ultra sensitive personal financial ledger & credentials';

    // 1. Setup vault with oldPassword
    const setupResult = await client.setupVault(vaultId, oldPassword, secretContent);

    // 2. Simulate forgotten password: normal login with oldPassword succeeds, wrong password fails
    await assert.rejects(
      () => client.login(vaultId, 'IncorrectForgotGuess'),
      /Vault decryption authentication failed|unable to authenticate/
    );

    // 3. User runs Forgot Password (U + S) using local User Share U (id: 1)
    const resetResult = await client.forgotPasswordReset({
      vaultId,
      userShare: setupResult.userShare,
      newPassword,
    });

    assert.strictEqual(resetResult.vaultId, vaultId);
    assert.strictEqual(resetResult.plaintext, secretContent);
    assert.strictEqual(resetResult.passwordReset, true);
    assert.deepStrictEqual(resetResult.dataKey, setupResult.dataKey);

    // 4. Verify login with NEW password succeeds
    const newLoginResult = await client.login(vaultId, newPassword);
    assert.strictEqual(newLoginResult.plaintext, secretContent);
    assert.deepStrictEqual(newLoginResult.dataKey, setupResult.dataKey);

    // 5. Verify login with OLD password now fails (tag check authentication failure)
    await assert.rejects(
      () => client.login(vaultId, oldPassword),
      /Vault decryption authentication failed|unable to authenticate/
    );

    // 6. Verify Service Provider Audit Log contains PASSWORD_RESET event
    const spAuditHistory = spStorage.auditLog.getEvents();
    const pwResetEvent = spAuditHistory.find(
      (e) => e.action === 'PASSWORD_RESET' && (e.payload as any).vaultId === vaultId
    );
    assert.ok(pwResetEvent, 'SP Audit Log must record PASSWORD_RESET event');
  });

  it('PROVE: Algorithm 2 (U + E) recovery with Schnorr challenge-response and automatic key rotation (Steps 8-9)', async () => {
    const vaultId = 'algo2-rotation-vault-606';
    const password = 'PasswordAlgo2#2026';
    const secretContent = 'Algo 2 Confidential Payload: Medical Records & Legal Documents';
    const aadhaarNumber = '444455556666';

    aadhaarService.registerProfile({
      aadhaarNumber,
      phoneNumber: '+91-6666666666',
      name: 'David Resident',
    });

    // 1. Setup vault and register with Escrow Cluster
    const setupResult = await client.setupVault(vaultId, password, secretContent);
    await client.registerWithEscrow(
      vaultId,
      setupResult.escrowShare,
      setupResult.schnorrKeys.publicKeyHex,
      aadhaarNumber
    );

    // 2. Perform Algorithm 2 Recovery (U + E)
    const algo2Result = await client.recoverVaultAlgorithm2({
      vaultId,
      userShare: setupResult.userShare,
      clientPrivateKey: setupResult.schnorrKeys.privateKey,
      otpProvider: (init) => init.mockOtp!,
      customDelayMs: 20,
      rotateClientKeys: true,
    });

    // 3. Verify vault decryption
    assert.strictEqual(algo2Result.vaultId, vaultId);
    assert.strictEqual(algo2Result.plaintext, secretContent);
    assert.deepStrictEqual(algo2Result.dataKey, setupResult.dataKey);
    assert.strictEqual(algo2Result.sharesUsed.share1Id, 1, 'Used User Share U');
    assert.strictEqual(algo2Result.sharesUsed.share2Id, 3, 'Used Escrow Share E');

    // 4. Verify Automatic Key Rotation (Steps 8 & 9)
    assert.strictEqual(algo2Result.rotated, true);
    assert.ok(algo2Result.newUserShare);
    assert.strictEqual(algo2Result.newUserShare.id, 1, 'Fresh User Share U\' has id: 1');
    assert.notDeepStrictEqual(algo2Result.newUserShare.data, setupResult.userShare.data, 'Fresh U\' must differ from old U');

    assert.ok(algo2Result.newEscrowShare);
    assert.strictEqual(algo2Result.newEscrowShare.id, 3, 'Fresh Escrow Share E\' has id: 3');
    assert.notDeepStrictEqual(algo2Result.newEscrowShare.data, setupResult.escrowShare.data, 'Fresh E\' must differ from old E');

    assert.ok(algo2Result.escrowCheckpoint, 'Escrow must produce signed Merkle root checkpoint');

    // 5. Verify Old Shares are revoked and no longer reconstruct the active K_rec'
    const spCurrentData = spStorage.getRecoveryData(vaultId);
    const staleKRec = reconstructRecoveryKey([setupResult.userShare, spCurrentData.spShare]);
    // Attempting to unwrap with old K_rec must fail because W_rec was rotated to W_rec'!
    assert.throws(
      () => unwrapKey(spCurrentData.wrappedKeyRec, staleKRec),
      /Vault decryption authentication failed|unable to authenticate/
    );

    // 6. Verify Fresh Shares (U' + S') successfully reconstruct active K_rec' and unwrap K_data
    const validFreshKRec = reconstructRecoveryKey([algo2Result.newUserShare, spCurrentData.spShare]);
    const unwrappedKData = unwrapKey(spCurrentData.wrappedKeyRec, validFreshKRec);
    assert.deepStrictEqual(unwrappedKData, setupResult.dataKey);

    // 7. Verify Audit Logs on both SP and Escrow recorded Key Rotation
    const spEvents = spStorage.auditLog.getEvents();
    assert.ok(spEvents.some((e) => e.action === 'RECOVERY_KEY_ROTATED' && (e.payload as any).vaultId === vaultId));

    const escrowEvents = escrowCoordinator.auditLog.getEvents();
    assert.ok(escrowEvents.some((e) => e.action === 'NODE_SHARES_REVOKED' && (e.payload as any).vaultId === vaultId));
    assert.ok(escrowEvents.some((e) => e.action === 'ESCROW_KEY_ROTATED' && (e.payload as any).vaultId === vaultId));
  });

  it('PROVE: Algorithm 4 (S + E) Total Loss recovery in Recoverable Mode with automatic key rotation and device provisioning (Step 5)', async () => {
    const vaultId = 'algo4-totalloss-vault-707';
    const originalPassword = 'InitialDevicePassword#707';
    const newDevicePassword = 'NewDeviceFreshPassword#707!';
    const secretContent = 'Total Loss Protected Content: Corporate Cryptographic Root Certificates';
    const aadhaarNumber = '333344445555';

    aadhaarService.registerProfile({
      aadhaarNumber,
      phoneNumber: '+91-5555555555',
      name: 'Elena Resident',
    });

    // 1. Setup vault in RECOVERABLE mode (default)
    const setupResult = await client.setupVault(vaultId, originalPassword, secretContent, {
      recoveryMode: 'RECOVERABLE',
    });
    assert.strictEqual(setupResult.recoveryMode, 'RECOVERABLE');

    await client.registerWithEscrow(
      vaultId,
      setupResult.escrowShare,
      setupResult.schnorrKeys.publicKeyHex,
      aadhaarNumber,
      'RECOVERABLE'
    );

    // 2. Total Device Loss Scenario: User lost both initial password and local User Share U
    // User executes Algorithm 4 (Total Loss S + E recovery) from a brand new device
    const algo4Result = await client.recoverVaultAlgorithm4({
      vaultId,
      clientPrivateKey: setupResult.schnorrKeys.privateKey,
      otpProvider: (init) => init.mockOtp!,
      customDelayMs: 20,
      newPassword: newDevicePassword,
    });

    // 3. Verify vault payload recovered
    assert.strictEqual(algo4Result.vaultId, vaultId);
    assert.strictEqual(algo4Result.plaintext, secretContent);
    assert.deepStrictEqual(algo4Result.dataKey, setupResult.dataKey);
    assert.strictEqual(algo4Result.sharesUsed.share1Id, 2, 'Used SP Share S (id: 2)');
    assert.strictEqual(algo4Result.sharesUsed.share2Id, 3, 'Used Escrow Share E (id: 3)');

    // 4. Verify Step 5 automatic key rotation & new device credentials
    assert.strictEqual(algo4Result.rotated, true);
    assert.ok(algo4Result.newUserShare, 'New client device receives fresh User Share U\'');
    assert.strictEqual(algo4Result.newUserShare.id, 1);
    assert.ok(algo4Result.newSchnorrKeys, 'New client device receives fresh Schnorr keypair');
    assert.strictEqual(algo4Result.passwordReset, true);

    // 5. Verify normal login works immediately on new device using newDevicePassword
    const newDeviceLogin = await client.login(vaultId, newDevicePassword);
    assert.strictEqual(newDeviceLogin.plaintext, secretContent);
    assert.deepStrictEqual(newDeviceLogin.dataKey, setupResult.dataKey);

    // Old password must fail
    await assert.rejects(
      () => client.login(vaultId, originalPassword),
      /Vault decryption authentication failed|unable to authenticate/
    );

    // 6. Verify Escrow signed checkpoint
    assert.ok(algo4Result.escrowCheckpoint);
  });

  it('PROVE: Strict Mode enforcement strictly disables S + E total loss recovery while allowing U-assisted recovery', async () => {
    const vaultId = 'strict-mode-vault-808';
    const password = 'StrictVaultMasterPassword#808';
    const secretContent = 'Top Secret Vault: S+E Collusion Resistance Active';
    const aadhaarNumber = '222233334444';

    aadhaarService.registerProfile({
      aadhaarNumber,
      phoneNumber: '+91-4444444444',
      name: 'Frank Strict',
    });

    // 1. Setup vault with recoveryMode: 'STRICT'
    const setupResult = await client.setupVault(vaultId, password, secretContent, {
      recoveryMode: 'STRICT',
    });
    assert.strictEqual(setupResult.recoveryMode, 'STRICT');

    await client.registerWithEscrow(
      vaultId,
      setupResult.escrowShare,
      setupResult.schnorrKeys.publicKeyHex,
      aadhaarNumber,
      'STRICT'
    );

    // 2. Attempt Algorithm 4 (S + E Total Loss) -> MUST BE REJECTED!
    await assert.rejects(
      () =>
        client.recoverVaultAlgorithm4({
          vaultId,
          clientPrivateKey: setupResult.schnorrKeys.privateKey,
          otpProvider: (init) => init.mockOtp!,
          customDelayMs: 20,
        }),
      /Strict Mode Violation.*STRICT mode.*Total loss S\+E recovery is strictly disabled/
    );

    // 3. User with User Share U CAN still recover via Forgot Password (U + S)
    const resetResult = await client.forgotPasswordReset({
      vaultId,
      userShare: setupResult.userShare,
      newPassword: 'NewStrictPassword#808!',
    });
    assert.strictEqual(resetResult.plaintext, secretContent);

    // 4. User with User Share U CAN also recover via Algorithm 2 (U + E)
    const algo2Result = await client.recoverVaultAlgorithm2({
      vaultId,
      userShare: setupResult.userShare,
      clientPrivateKey: setupResult.schnorrKeys.privateKey,
      otpProvider: (init) => init.mockOtp!,
      customDelayMs: 20,
    });
    assert.strictEqual(algo2Result.plaintext, secretContent);
    assert.strictEqual(algo2Result.rotated, true);
  });
});
