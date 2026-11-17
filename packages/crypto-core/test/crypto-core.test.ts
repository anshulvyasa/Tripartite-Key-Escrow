import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateDataKey,
  generateRandomBytes,
  encryptVault,
  decryptVault,
  wrapKey,
  unwrapKey,
  derivePasswordKey,
  generateSalt,
  FAST_TEST_ARGON2_PARAMS,
  splitSecret2of3,
  reconstructSecret2of3,
  splitRecoveryKey,
  reconstructRecoveryKey,
  splitEscrowShare,
  reconstructEscrowShare,
  reconstructFromHierarchicalShares,
  InsufficientSharesError,
  InvalidShareError,
  generateSchnorrKeyPair,
  createSchnorrChallenge,
  signSchnorrChallenge,
  verifySchnorrChallenge,
} from '../src/index.ts';

describe('packages/crypto-core Test Suite', () => {
  // =========================================================================
  // 1. AES-256-GCM Vault Encryption & Key Wrapping
  // =========================================================================
  describe('AES-256-GCM Vault Encryption & Wrapping', () => {
    it('should successfully encrypt and decrypt vault payload', () => {
      const dataKey = generateDataKey();
      const vaultContent = JSON.stringify({
        documents: ['passport.pdf', 'tax_returns.enc'],
        secretNotes: 'High-security financial ledger',
      });

      const encrypted = encryptVault(vaultContent, dataKey, 'metadata-tenant-01');
      assert.ok(encrypted.ciphertext);
      assert.ok(encrypted.iv);
      assert.ok(encrypted.tag);

      const decryptedBytes = decryptVault(encrypted, dataKey, 'metadata-tenant-01');
      const decryptedText = new TextDecoder().decode(decryptedBytes);
      assert.strictEqual(decryptedText, vaultContent);
    });

    it('should fail decryption if ciphertext or auth tag is tampered', () => {
      const dataKey = generateDataKey();
      const payload = 'Confidential Patient Records';
      const encrypted = encryptVault(payload, dataKey);

      // Tamper with ciphertext by corrupting bytes
      const rawCt = Buffer.from(encrypted.ciphertext, 'base64');
      rawCt[0] ^= 0xff; // Flip bits
      const tampered = { ...encrypted, ciphertext: rawCt.toString('base64') };

      assert.throws(
        () => decryptVault(tampered, dataKey),
        /Vault decryption authentication failed/
      );
    });

    it('should fail decryption if Additional Authenticated Data (AAD) does not match', () => {
      const dataKey = generateDataKey();
      const payload = 'Restricted Cloud Backup';
      const encrypted = encryptVault(payload, dataKey, 'expected-aad-org-99');

      assert.throws(
        () => decryptVault(encrypted, dataKey, 'wrong-aad-attacker'),
        /Vault decryption authentication failed/
      );
    });

    it('should successfully wrap and unwrap Data Key (K_data) under a wrapping key', () => {
      const kData = generateDataKey();
      const wrappingKey = generateDataKey(); // e.g. K_pw or K_rec

      const wrapped = wrapKey(kData, wrappingKey);
      assert.ok(wrapped.wrappedKey);
      assert.ok(wrapped.iv);
      assert.ok(wrapped.tag);

      const unwrapped = unwrapKey(wrapped, wrappingKey);
      assert.deepStrictEqual(unwrapped, kData);
    });
  });

  // =========================================================================
  // 2. Argon2id Key Derivation & Password Wrapping Checks
  // =========================================================================
  describe('Argon2id Key Derivation & Authentication Checks', () => {
    it('should deterministically derive 256-bit key from password and salt', () => {
      const password = 'CorrectHorseBatteryStaple-2026!';
      const salt = generateSalt(16);

      const key1 = derivePasswordKey(password, salt, FAST_TEST_ARGON2_PARAMS);
      const key2 = derivePasswordKey(password, salt, FAST_TEST_ARGON2_PARAMS);

      assert.strictEqual(key1.length, 32);
      assert.deepStrictEqual(key1, key2);
    });

    it('PROVE: wrong Argon2id passwords fail the AES-GCM tag check when unwrapping K_data', () => {
      const correctPassword = 'MyVaultPassword#Secure123';
      const wrongPassword = 'MyVaultPassword#WrongAttempt';
      const salt = generateSalt(16);

      // 1. Generate real vault Data Key K_data
      const kData = generateDataKey();

      // 2. Derive K_pw using correct password and wrap K_data
      const kPwCorrect = derivePasswordKey(correctPassword, salt, FAST_TEST_ARGON2_PARAMS);
      const wrappedKData = wrapKey(kData, kPwCorrect);

      // 3. User attempts login with WRONG password -> produces wrong K_pw
      const kPwWrong = derivePasswordKey(wrongPassword, salt, FAST_TEST_ARGON2_PARAMS);
      assert.notDeepStrictEqual(kPwWrong, kPwCorrect);

      // 4. Attempting to unwrap with wrong key MUST fail the GCM authentication tag check
      assert.throws(
        () => unwrapKey(wrappedKData, kPwWrong),
        /Vault decryption authentication failed/
      );

      // 5. Unwrapping with correct key succeeds and recovers original K_data
      const recoveredKData = unwrapKey(wrappedKData, kPwCorrect);
      assert.deepStrictEqual(recoveredKData, kData);
    });
  });

  // =========================================================================
  // 3. Two-Tier Shamir Secret Sharing (2-of-3 Threshold)
  // =========================================================================
  describe('Two-Tier Shamir Secret Sharing (t=2, n=3)', () => {
    it('PROVE: any 2 shares reconstruct K_rec at Tier 1 (all combinations)', () => {
      const kRec = generateDataKey(); // 32-byte Recovery Key
      const { userShare, spShare, escrowShare } = splitRecoveryKey(kRec);

      assert.strictEqual(userShare.id, 1);
      assert.strictEqual(spShare.id, 2);
      assert.strictEqual(escrowShare.id, 3);

      // Combination 1: User Share (U) + SP Share (S)
      const reconUS = reconstructRecoveryKey([userShare, spShare]);
      assert.deepStrictEqual(reconUS, kRec, 'Combination U + S must reconstruct K_rec');

      // Combination 2: User Share (U) + Escrow Share (E)
      const reconUE = reconstructRecoveryKey([userShare, escrowShare]);
      assert.deepStrictEqual(reconUE, kRec, 'Combination U + E must reconstruct K_rec');

      // Combination 3: SP Share (S) + Escrow Share (E)
      const reconSE = reconstructRecoveryKey([spShare, escrowShare]);
      assert.deepStrictEqual(reconSE, kRec, 'Combination S + E must reconstruct K_rec');
    });

    it('PROVE: 1 share fails to reconstruct (insufficient threshold)', () => {
      const kRec = generateDataKey();
      const { userShare, spShare, escrowShare } = splitRecoveryKey(kRec);

      // Single share attempts must fail and throw InsufficientSharesError
      assert.throws(
        () => reconstructRecoveryKey([userShare]),
        InsufficientSharesError,
        'User share alone must fail'
      );

      assert.throws(
        () => reconstructRecoveryKey([spShare]),
        InsufficientSharesError,
        'SP share alone must fail'
      );

      assert.throws(
        () => reconstructRecoveryKey([escrowShare]),
        InsufficientSharesError,
        'Escrow share alone must fail'
      );

      // Empty share array must also fail
      assert.throws(
        () => reconstructRecoveryKey([]),
        InsufficientSharesError
      );
    });

    it('should reject duplicate shares (e.g. providing [U, U])', () => {
      const kRec = generateDataKey();
      const { userShare } = splitRecoveryKey(kRec);

      // Duplicate share cannot satisfy 2-of-3 requirement
      assert.throws(
        () => reconstructRecoveryKey([userShare, userShare]),
        InvalidShareError
      );
    });

    it('PROVE: Escrow Share (E) sub-splitting across N1, N2, N3 (Tier 2)', () => {
      const kRec = generateDataKey();
      const { escrowShare } = splitRecoveryKey(kRec);

      // Split E into N1, N2, N3
      const { n1Share, n2Share, n3Share } = splitEscrowShare(escrowShare);

      assert.strictEqual(n1Share.id, 1);
      assert.strictEqual(n2Share.id, 2);
      assert.strictEqual(n3Share.id, 3);

      // Sub-combination 1: N1 + N2
      const reconE_12 = reconstructEscrowShare([n1Share, n2Share]);
      assert.strictEqual(reconE_12.id, 3);
      assert.strictEqual(reconE_12.data, escrowShare.data, 'N1 + N2 must reconstruct E');

      // Sub-combination 2: N1 + N3
      const reconE_13 = reconstructEscrowShare([n1Share, n3Share]);
      assert.strictEqual(reconE_13.data, escrowShare.data, 'N1 + N3 must reconstruct E');

      // Sub-combination 3: N2 + N3
      const reconE_23 = reconstructEscrowShare([n2Share, n3Share]);
      assert.strictEqual(reconE_23.data, escrowShare.data, 'N2 + N3 must reconstruct E');

      // Single escrow sub-share must fail
      assert.throws(
        () => reconstructEscrowShare([n1Share]),
        InsufficientSharesError,
        'Single node share N1 alone must fail'
      );
    });

    it('PROVE: Full Hierarchical End-to-End Recovery (User + 2 Escrow Nodes & SP + 2 Escrow Nodes)', () => {
      // Setup full system keys
      const kData = generateDataKey();
      const kRec = generateDataKey();

      // Wrap K_data under K_rec
      const recoveryWrappedKData = wrapKey(kData, kRec);

      // Encrypt vault under K_data
      const vaultSecret = 'Top secret personal digital locker';
      const vaultEncrypted = encryptVault(vaultSecret, kData);

      // Tier 1: Split K_rec into U, S, E
      const { userShare, spShare, escrowShare } = splitRecoveryKey(kRec);

      // Tier 2: Split E into N1, N2, N3
      const { n1Share, n2Share, n3Share } = splitEscrowShare(escrowShare);

      // Case A: Disaster recovery using User Share (U) + Escrow Nodes (N1, N2)
      const reconKRec_CaseA = reconstructFromHierarchicalShares(userShare, [n1Share, n2Share]);
      assert.deepStrictEqual(reconKRec_CaseA, kRec);

      const unwrappedKData_CaseA = unwrapKey(recoveryWrappedKData, reconKRec_CaseA);
      assert.deepStrictEqual(unwrappedKData_CaseA, kData);

      const recoveredVault_CaseA = decryptVault(vaultEncrypted, unwrappedKData_CaseA);
      assert.strictEqual(new TextDecoder().decode(recoveredVault_CaseA), vaultSecret);

      // Case B: Disaster recovery using SP Share (S) + Escrow Nodes (N2, N3)
      const reconKRec_CaseB = reconstructFromHierarchicalShares(spShare, [n2Share, n3Share]);
      assert.deepStrictEqual(reconKRec_CaseB, kRec);

      const unwrappedKData_CaseB = unwrapKey(recoveryWrappedKData, reconKRec_CaseB);
      assert.deepStrictEqual(unwrappedKData_CaseB, kData);

      const recoveredVault_CaseB = decryptVault(vaultEncrypted, unwrappedKData_CaseB);
      assert.strictEqual(new TextDecoder().decode(recoveredVault_CaseB), vaultSecret);
    });
  });

  // =========================================================================
  // 4. Zero-Knowledge Identity: Schnorr Challenge-Response Signatures
  // =========================================================================
  describe('Zero-Knowledge Schnorr Challenge-Response', () => {
    it('PROVE: Schnorr challenge-response succeeds for valid client keypair', () => {
      // 1. Client generates keypair locally
      const clientKeys = generateSchnorrKeyPair();
      assert.strictEqual(clientKeys.privateKey.length, 32);
      assert.strictEqual(clientKeys.publicKey.length, 32);

      // 2. Client registers ONLY public key with Escrow
      const registeredPubKeyHex = clientKeys.publicKeyHex;

      // 3. Escrow issues challenge nonce
      const challenge = createSchnorrChallenge('recovery-session-user-123');
      assert.ok(challenge.nonce);
      assert.ok(challenge.timestamp > 0);

      // 4. Client signs challenge locally using sk_rec
      const signatureHex = signSchnorrChallenge(challenge, clientKeys.privateKey);
      assert.strictEqual(Buffer.from(signatureHex, 'hex').length, 64);

      // 5. Escrow verifies challenge response without ever seeing private key
      const isVerified = verifySchnorrChallenge(challenge, signatureHex, registeredPubKeyHex);
      assert.strictEqual(isVerified, true, 'Valid challenge response must verify');
    });

    it('should reject tampered challenge nonce', () => {
      const clientKeys = generateSchnorrKeyPair();
      const originalChallenge = createSchnorrChallenge();
      const signatureHex = signSchnorrChallenge(originalChallenge, clientKeys.privateKey);

      // Attacker tampers with challenge nonce
      const tamperedChallenge = {
        ...originalChallenge,
        nonce: generateRandomBytes(32).toString(),
      };

      const isValid = verifySchnorrChallenge(tamperedChallenge, signatureHex, clientKeys.publicKeyHex);
      assert.strictEqual(isValid, false, 'Tampered challenge must fail verification');
    });

    it('should reject signature from an unauthorized private key', () => {
      const legitimateClient = generateSchnorrKeyPair();
      const maliciousImpostor = generateSchnorrKeyPair();

      const challenge = createSchnorrChallenge();

      // Impostor signs challenge
      const impostorSig = signSchnorrChallenge(challenge, maliciousImpostor.privateKey);

      // Escrow verifies against legitimate client's registered public key
      const isValid = verifySchnorrChallenge(challenge, impostorSig, legitimateClient.publicKeyHex);
      assert.strictEqual(isValid, false, 'Signature from unauthorized key must be rejected');
    });

    it('should reject corrupted signature bytes', () => {
      const clientKeys = generateSchnorrKeyPair();
      const challenge = createSchnorrChallenge();
      const signatureHex = signSchnorrChallenge(challenge, clientKeys.privateKey);

      // Corrupt 1 byte of the 64-byte signature
      const sigBuf = Buffer.from(signatureHex, 'hex');
      sigBuf[10] ^= 0xaa;
      const corruptedSigHex = sigBuf.toString('hex');

      const isValid = verifySchnorrChallenge(challenge, corruptedSigHex, clientKeys.publicKeyHex);
      assert.strictEqual(isValid, false, 'Corrupted signature must be rejected');
    });
  });
});
