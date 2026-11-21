import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ServiceProviderServer } from '../src/server.ts';
import { VaultStorage } from '../src/storage.ts';
import { VaultClient } from '@trivault/client';
import { FAST_TEST_ARGON2_PARAMS } from '@trivault/crypto-core';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const certsDir = path.resolve(__dirname, '../../../certs');

describe('Service Provider & Client Vault Integration (Algorithms 1 & 3)', () => {
  let spServer: ServiceProviderServer;
  let spStorage: VaultStorage;
  let client: VaultClient;
  const pipePath = `\\\\.\\pipe\\trivault-sp-integration-${Date.now()}`;

  before(async () => {
    spStorage = new VaultStorage();
    spServer = new ServiceProviderServer({
      storage: spStorage,
      certsDir,
      enableMTLS: true,
    });

    await spServer.start(pipePath);

    client = new VaultClient({
      spUrl: pipePath,
      certsDir,
      enableMTLS: true,
      argon2Params: FAST_TEST_ARGON2_PARAMS,
    });
  });

  after(async () => {
    await spServer.stop();
  });

  it('PROVE: Algorithm 1 (Setup) and Algorithm 3 (Login) full roundtrip with zero-knowledge SP boundary', async () => {
    const vaultId = 'vault-user-42';
    const correctPassword = 'CorrectMasterPassword#2026!';
    const wrongPassword = 'IncorrectAttackerGuess#9999!';
    const secretContent = JSON.stringify({
      bankingPin: '8492',
      cryptoWalletSeed: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      backupCodes: ['A1B2-C3D4', 'E5F6-G7H8'],
    });

    // =========================================================================
    // STEP 1: Algorithm 1 (Vault Setup)
    // =========================================================================
    const setupResult = await client.setupVault(vaultId, correctPassword, secretContent);

    assert.strictEqual(setupResult.vaultId, vaultId);
    assert.ok(setupResult.userShare);
    assert.strictEqual(setupResult.userShare.id, 1, 'Client must retain User Share U (id: 1)');
    assert.ok(setupResult.escrowShare);
    assert.strictEqual(setupResult.escrowShare.id, 3, 'Client must receive Escrow Share E (id: 3) for cluster escrow');
    assert.ok(setupResult.schnorrKeys.privateKey);
    assert.ok(setupResult.schnorrKeys.publicKey);
    assert.strictEqual(setupResult.dataKey.length, 32);

    // =========================================================================
    // STEP 2: Strict Service Provider Invariant Check
    // "Ensure the SP only ever stores ciphertext, the Argon2id salt,
    // the K_pw-wrapped data key, and Share S."
    // =========================================================================
    const storedRecord = spStorage.getLoginData(vaultId);
    const fullStoredRecord = spStorage.getRecoveryData(vaultId);

    // 1. Assert SP stores ciphertext and auth tag, NOT plaintext
    assert.ok(storedRecord.vaultCiphertext.ciphertext);
    assert.ok(storedRecord.vaultCiphertext.iv);
    assert.ok(storedRecord.vaultCiphertext.tag);
    assert.strictEqual(
      typeof storedRecord.vaultCiphertext.ciphertext,
      'string',
      'Vault content must be stored as ciphertext string'
    );
    assert.strictEqual(
      storedRecord.vaultCiphertext.ciphertext.includes('bankingPin'),
      false,
      'SP must never store plaintext records'
    );

    // 2. Assert SP stores Argon2id salt
    assert.ok(storedRecord.salt);
    assert.strictEqual(typeof storedRecord.salt, 'string');

    // 3. Assert SP stores K_pw-wrapped data key
    assert.ok(storedRecord.wrappedKeyPw.wrappedKey);
    assert.ok(storedRecord.wrappedKeyPw.iv);
    assert.ok(storedRecord.wrappedKeyPw.tag);

    // 4. Assert SP stores Share S (id: 2)
    assert.ok(fullStoredRecord.spShare);
    assert.strictEqual(fullStoredRecord.spShare.id, 2, 'SP must only hold Share S (id: 2)');

    // 5. Assert SP NEVER stores User Share U (id: 1) or Escrow Share E (id: 3)
    assert.strictEqual((storedRecord as any).userShare, undefined);
    assert.strictEqual((storedRecord as any).escrowShare, undefined);

    // 6. Assert SP NEVER stores plaintext password or raw keys
    assert.strictEqual((storedRecord as any).password, undefined);
    assert.strictEqual((storedRecord as any).kData, undefined);
    assert.strictEqual((storedRecord as any).kRec, undefined);

    // =========================================================================
    // STEP 3: Algorithm 3 (Normal Daily Login) with Correct Password
    // =========================================================================
    const loginResult = await client.login(vaultId, correctPassword);

    assert.strictEqual(loginResult.vaultId, vaultId);
    assert.deepStrictEqual(
      loginResult.dataKey,
      setupResult.dataKey,
      'Locally unwrapped K_data must match original active session key'
    );
    assert.strictEqual(
      loginResult.plaintext,
      secretContent,
      'Decrypted vault payload must exactly match original secret'
    );

    // =========================================================================
    // STEP 4: Algorithm 3 (Login) with WRONG Password MUST Fail Tag Check
    // =========================================================================
    await assert.rejects(
      () => client.login(vaultId, wrongPassword),
      (err: any) => {
        // Must fail the AES-256-GCM authentication tag check when unwrapping K_data
        return (
          err.message.includes('Vault decryption authentication failed') ||
          err.message.includes('unable to authenticate data') ||
          err.message.includes('Unsupported state')
        );
      },
      'Wrong password MUST cause AES-GCM tag verification failure when unwrapping K_data'
    );

    // =========================================================================
    // STEP 5: Vault Content Update Roundtrip
    // =========================================================================
    const updatedContent = JSON.stringify({
      bankingPin: '9901',
      notes: 'Updated personal notes after successful daily login',
    });

    await client.updateVault(vaultId, loginResult.dataKey, updatedContent);

    // Subsequent login recovers the newly encrypted ciphertext
    const secondLogin = await client.login(vaultId, correctPassword);
    assert.strictEqual(secondLogin.plaintext, updatedContent);

    // =========================================================================
    // STEP 6: Service Provider Audit Log Chain Verification
    // =========================================================================
    const auditVerification = spStorage.auditLog.verifyChainIntegrity();
    assert.strictEqual(auditVerification.valid, true);
    assert.ok(auditVerification.totalEvents >= 3);
  });

  it('PROVE: Service Provider rejects setup requests that attempt to leak forbidden secrets', () => {
    const maliciousPayloadWithPassword = {
      vaultId: 'malicious-vault-001',
      salt: '0123456789abcdef0123456789abcdef',
      wrappedKeyPw: { wrappedKey: 'abc', iv: 'def', tag: 'ghi' },
      wrappedKeyRec: { wrappedKey: 'abc', iv: 'def', tag: 'ghi' },
      spShare: { id: 2, data: '112233' },
      vaultCiphertext: { ciphertext: 'abc', iv: 'def', tag: 'ghi' },
      // FORBIDDEN FIELD:
      password: 'PlaintextUserPassword123!',
    };

    assert.throws(
      () => spStorage.createVault(maliciousPayloadWithPassword as any, maliciousPayloadWithPassword),
      /Security Invariant Violation: Service Provider must never receive 'password'/
    );

    const maliciousPayloadWithWrongShare = {
      vaultId: 'malicious-vault-002',
      salt: '0123456789abcdef0123456789abcdef',
      wrappedKeyPw: { wrappedKey: 'abc', iv: 'def', tag: 'ghi' },
      wrappedKeyRec: { wrappedKey: 'abc', iv: 'def', tag: 'ghi' },
      // FORBIDDEN: Trying to send User Share U (id: 1) to SP
      spShare: { id: 1, data: '112233' },
      vaultCiphertext: { ciphertext: 'abc', iv: 'def', tag: 'ghi' },
    };

    assert.throws(
      () => spStorage.createVault(maliciousPayloadWithWrongShare as any, maliciousPayloadWithWrongShare),
      /Security Invariant Violation: Service Provider must only store Share S \(id: 2\)/
    );
  });
});
