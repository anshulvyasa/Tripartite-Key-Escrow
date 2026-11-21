import http from 'node:http';
import https from 'node:https';
import {
  generateDataKey,
  generateSalt,
  derivePasswordKey,
  wrapKey,
  unwrapKey,
  encryptVault,
  decryptVault,
  splitRecoveryKey,
  generateSchnorrKeyPair,
  reconstructRecoveryKey,
  signSchnorrChallenge,
  FAST_TEST_ARGON2_PARAMS,
  type Argon2Params,
  type ShamirShare,
  type SchnorrKeyPair,
} from '@trivault/crypto-core';
import { getMTLSClientOptions, isMTLSEnabled } from '@trivault/certs';
import type {
  VaultSetupResult,
  VaultLoginResult,
  VaultClientConfig,
  EscrowRegistrationResult,
  RecoveryInitiationResult,
  RecoveryProofResult,
  RecoveryCompleteResult,
  VaultRecoveryResult,
  ForgotPasswordResult,
  Algorithm2RecoveryResult,
  Algorithm4RecoveryResult,
  SetupVaultOptions,
  RecoveryMode,
} from './types.ts';

export class VaultClient {
  private readonly config: VaultClientConfig;

  constructor(config: VaultClientConfig) {
    this.config = config;
  }

  /**
   * Helper to perform HTTP or HTTPS (mTLS) requests to a target service (SP or Escrow Cluster).
   * Supports both TCP URLs and named pipes.
   */
  private async request(
    method: 'GET' | 'POST' | 'PUT',
    path: string,
    body?: any,
    targetUrl?: string
  ): Promise<any> {
    const baseUrl = targetUrl || this.config.spUrl;
    const isPipe = baseUrl.startsWith('\\\\.\\pipe\\');
    const mtlsActive = isMTLSEnabled(this.config.enableMTLS);

    let clientOpts: any = {};
    if (mtlsActive) {
      clientOpts = getMTLSClientOptions('client', {
        certsDir: this.config.certsDir,
        enableMTLS: true,
      });
    }

    const payloadStr = body ? JSON.stringify(body) : undefined;

    return new Promise((resolve, reject) => {
      const headers: Record<string, string> = {
        'Accept': 'application/json',
      };
      if (payloadStr) {
        headers['Content-Type'] = 'application/json';
        headers['Content-Length'] = Buffer.byteLength(payloadStr).toString();
      }

      let reqOptions: https.RequestOptions | http.RequestOptions;
      let isHttps = mtlsActive;

      if (isPipe) {
        reqOptions = {
          socketPath: baseUrl,
          path,
          method,
          headers,
          ...(mtlsActive ? clientOpts : {}),
        };
      } else {
        const parsedUrl = new URL(path, baseUrl);
        isHttps = parsedUrl.protocol === 'https:';
        reqOptions = {
          protocol: parsedUrl.protocol,
          hostname: parsedUrl.hostname,
          port: parsedUrl.port || (isHttps ? 443 : 80),
          path: parsedUrl.pathname + parsedUrl.search,
          method,
          headers,
          ...(isHttps ? clientOpts : {}),
        };
      }

      const transport = isHttps ? https : http;
      const req = transport.request(reqOptions, (res) => {
        let resData = '';
        res.on('data', (chunk) => (resData += chunk));
        res.on('end', () => {
          try {
            const json = resData ? JSON.parse(resData) : {};
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
              resolve(json);
            } else {
              reject(new Error(json.error || `HTTP ${res.statusCode}: Request failed`));
            }
          } catch {
            reject(new Error(`Failed to parse response (HTTP ${res.statusCode}): ${resData}`));
          }
        });
      });

      req.on('error', reject);
      if (payloadStr) {
        req.write(payloadStr);
      }
      req.end();
    });
  }

  /**
   * ALGORITHM 1: Vault Setup
   *
   * 1. Generates local symmetric Data Key (K_data) for AES-256-GCM.
   * 2. Generates fresh salt and derives K_pw via Argon2id(password, salt).
   * 3. Wraps K_data under K_pw -> W_pw.
   * 4. Generates local Recovery Key K_rec.
   * 5. Wraps K_data under K_rec -> W_rec.
   * 6. Splits K_rec into User Share (U), SP Share (S), and Escrow Share (E) via Shamir 2-of-3.
   * 7. Generates local Schnorr identity keypair (sk_rec, pk_rec).
   * 8. Encrypts initial plaintext with K_data -> vaultCiphertext.
   * 9. Transmits ONLY { salt, W_pw, W_rec, Share S, vaultCiphertext } to Service Provider.
   * 10. SP NEVER receives plaintext, password, K_data, K_rec, or Share U / E.
   */
  async setupVault(
    vaultId: string,
    password: string,
    initialPlaintext: string | Uint8Array,
    options?: SetupVaultOptions
  ): Promise<VaultSetupResult> {
    const recoveryMode = options?.recoveryMode || 'RECOVERABLE';

    // 1. Generate local K_data
    const dataKey = generateDataKey();

    // 2. Generate salt & derive K_pw
    const saltBytes = generateSalt(16);
    const saltHex = Buffer.from(saltBytes).toString('hex');
    const argonParams = this.config.argon2Params || FAST_TEST_ARGON2_PARAMS;
    const kPw = derivePasswordKey(password, saltBytes, argonParams);

    // 3. Wrap K_data under K_pw
    const wrappedKeyPw = wrapKey(dataKey, kPw);

    // 4. Generate K_rec & wrap K_data under K_rec
    const kRec = generateDataKey();
    const wrappedKeyRec = wrapKey(dataKey, kRec);

    // 5. Split K_rec into U, S, E (Shamir 2-of-3)
    const { userShare, spShare, escrowShare } = splitRecoveryKey(kRec);

    // 6. Generate Schnorr recovery identity keypair
    const schnorrKeys = generateSchnorrKeyPair();

    // 7. Encrypt initial vault payload
    const vaultCiphertext = encryptVault(initialPlaintext, dataKey);

    // 8. Transmit only authorized zero-knowledge metadata to Service Provider
    await this.request('POST', '/api/v1/vault/setup', {
      vaultId,
      salt: saltHex,
      wrappedKeyPw,
      wrappedKeyRec,
      spShare,
      vaultCiphertext,
      recoveryMode,
    });

    return {
      vaultId,
      userShare,
      escrowShare,
      schnorrKeys,
      salt: saltHex,
      dataKey,
      recoveryMode,
    };
  }

  /**
   * ALGORITHM 3: Normal Login
   *
   * 1. Fetches login metadata { salt, wrappedKeyPw, vaultCiphertext } from SP.
   * 2. Re-derives K_pw via Argon2id(password, salt).
   * 3. Locally unwraps K_data = unwrapKey(wrappedKeyPw, K_pw).
   *    -> FAILS with AES-GCM tag check error if password is incorrect!
   * 4. Locally decrypts vaultCiphertext with unwrapped K_data.
   * 5. SP never sees password, K_pw, K_data, or decrypted vault.
   */
  async login(vaultId: string, password: string): Promise<VaultLoginResult> {
    // 1. Fetch login metadata from Service Provider
    const loginData = await this.request('GET', `/api/v1/vault/${encodeURIComponent(vaultId)}/login-data`);

    // 2. Re-derive K_pw using the stored salt
    const saltBytes = Buffer.from(loginData.salt, 'hex');
    const argonParams = this.config.argon2Params || FAST_TEST_ARGON2_PARAMS;
    const kPw = derivePasswordKey(password, saltBytes, argonParams);

    // 3. Locally unwrap K_data
    // If password is wrong, unwrapKey throws "Vault decryption authentication failed"
    const dataKey = unwrapKey(loginData.wrappedKeyPw, kPw);

    // 4. Locally decrypt vault data
    const decryptedBytes = decryptVault(loginData.vaultCiphertext, dataKey);
    const plaintext = new TextDecoder().decode(decryptedBytes);

    return {
      vaultId,
      dataKey,
      plaintext,
      plaintextBytes: decryptedBytes,
    };
  }

  /**
   * Updates vault contents with a new plaintext payload using active session K_data.
   */
  async updateVault(
    vaultId: string,
    dataKey: Uint8Array,
    newPlaintext: string | Uint8Array
  ): Promise<void> {
    const vaultCiphertext = encryptVault(newPlaintext, dataKey);
    await this.request('PUT', `/api/v1/vault/${encodeURIComponent(vaultId)}/data`, {
      vaultCiphertext,
    });
  }

  /**
   * Registers a vault's Escrow Share (Share E) with the Escrow Cluster.
   * Splits E into N1, N2, N3 sub-shares across autonomous nodes.
   */
  async registerWithEscrow(
    vaultId: string,
    escrowShareE: ShamirShare,
    clientPubKeyHex: string,
    aadhaarNumber: string,
    recoveryMode: RecoveryMode = 'RECOVERABLE'
  ): Promise<EscrowRegistrationResult> {
    if (!this.config.escrowUrl) {
      throw new Error('Escrow Cluster URL (escrowUrl) is required to register with escrow.');
    }
    return this.request(
      'POST',
      '/api/v1/escrow/register',
      {
        vaultId,
        escrowShareE,
        clientPubKeyHex,
        aadhaarNumber,
        recoveryMode,
      },
      this.config.escrowUrl
    );
  }

  /**
   * Initiates the escrow recovery workflow.
   * Returns a Schnorr challenge and triggers Aadhaar OTP dispatch.
   */
  async initiateEscrowRecovery(
    vaultId: string,
    recoveryType: 'U_PLUS_E' | 'S_PLUS_E' = 'U_PLUS_E'
  ): Promise<RecoveryInitiationResult> {
    if (!this.config.escrowUrl) {
      throw new Error('Escrow Cluster URL (escrowUrl) is required for escrow recovery.');
    }
    return this.request(
      'POST',
      '/api/v1/escrow/recovery/initiate',
      { vaultId, recoveryType },
      this.config.escrowUrl
    );
  }

  /**
   * Submits Schnorr challenge-response signature and Aadhaar OTP to Escrow Coordinator.
   * Evaluates Policy Engine (HOW) and initiates timelock delay timer.
   */
  async submitEscrowRecoveryProof(
    requestId: string,
    schnorrSignatureHex: string,
    otp: string,
    customDelayMs?: number
  ): Promise<RecoveryProofResult> {
    if (!this.config.escrowUrl) {
      throw new Error('Escrow Cluster URL (escrowUrl) is required for escrow recovery.');
    }
    return this.request(
      'POST',
      '/api/v1/escrow/recovery/submit-proof',
      {
        requestId,
        schnorrSignatureHex,
        otp,
        customDelayMs,
      },
      this.config.escrowUrl
    );
  }

  /**
   * Aborts an unauthorized recovery session during the timelock delay window.
   */
  async cancelEscrowRecovery(
    requestId: string,
    reason: string = 'User requested cancellation'
  ): Promise<{ success: boolean; status: string; checkpoint: any }> {
    if (!this.config.escrowUrl) {
      throw new Error('Escrow Cluster URL (escrowUrl) is required to cancel recovery.');
    }
    return this.request(
      'POST',
      '/api/v1/escrow/recovery/cancel',
      {
        requestId,
        reason,
      },
      this.config.escrowUrl
    );
  }

  /**
   * Completes recovery after timelock delay expires.
   * Collects sub-shares from 2 escrow nodes and reconstructs Escrow Share E.
   */
  async completeEscrowRecovery(
    requestId: string,
    nodePair?: ['N1' | 'N2' | 'N3', 'N1' | 'N2' | 'N3']
  ): Promise<RecoveryCompleteResult> {
    if (!this.config.escrowUrl) {
      throw new Error('Escrow Cluster URL (escrowUrl) is required to complete recovery.');
    }
    return this.request(
      'POST',
      '/api/v1/escrow/recovery/complete',
      {
        requestId,
        nodePair,
      },
      this.config.escrowUrl
    );
  }

  /**
   * ALGORITHM 4: Reconstructs K_rec from any two valid 2-of-3 shares,
   * unwraps K_data, and decrypts the vault.
   */
  async recoverVaultFromShares(
    vaultId: string,
    share1: ShamirShare,
    share2: ShamirShare
  ): Promise<VaultRecoveryResult> {
    // 1. Fetch recovery data from Service Provider
    const recoveryData = await this.request(
      'GET',
      `/api/v1/vault/${encodeURIComponent(vaultId)}/recovery-data`
    );

    // 2. Reconstruct K_rec from the 2 provided shares
    const kRec = reconstructRecoveryKey([share1, share2]);

    // 3. Unwrap K_data = unwrapKey(wrappedKeyRec, kRec)
    const dataKey = unwrapKey(recoveryData.wrappedKeyRec, kRec);

    // 4. Decrypt vault ciphertext
    const decryptedBytes = decryptVault(recoveryData.vaultCiphertext, dataKey);
    const plaintext = new TextDecoder().decode(decryptedBytes);

    return {
      vaultId,
      dataKey,
      kRec,
      plaintext,
      plaintextBytes: decryptedBytes,
      sharesUsed: {
        share1Id: share1.id,
        share2Id: share2.id,
      },
    };
  }

  /**
   * Full end-to-end disaster recovery workflow:
   * 1. Fetches Share S from SP.
   * 2. Initiates escrow recovery -> gets Schnorr challenge.
   * 3. Signs challenge with client's Schnorr private key.
   * 4. Submits Schnorr signature and Aadhaar OTP to Escrow.
   * 5. Waits for timelock delay if necessary.
   * 6. Collects sub-shares from Escrow nodes and reconstructs Escrow Share E.
   * 7. Combines Share S + Share E to reconstruct K_rec, unwrap K_data, and decrypt the vault.
   */
  async recoverVaultWithEscrow(options: {
    vaultId: string;
    clientPrivateKey: Uint8Array | string;
    otp?: string;
    otpProvider?: (init: RecoveryInitiationResult) => Promise<string> | string;
    initSession?: RecoveryInitiationResult;
    customDelayMs?: number;
  }): Promise<VaultRecoveryResult> {
    const { vaultId, clientPrivateKey, customDelayMs } = options;

    // 1. Use existing or initiate fresh escrow recovery session
    const init = options.initSession || (await this.initiateEscrowRecovery(vaultId));

    // 2. Resolve OTP
    const otp = options.otpProvider ? await options.otpProvider(init) : options.otp;
    if (!otp) {
      throw new Error('Aadhaar OTP is required for recovery (provide otp or otpProvider).');
    }

    // 3. Sign Schnorr challenge
    const signature = signSchnorrChallenge(init.challenge, clientPrivateKey);

    // 4. Submit multi-factor proof
    const proof = await this.submitEscrowRecoveryProof(
      init.requestId,
      signature,
      otp,
      customDelayMs
    );

    // 5. Wait for timelock delay if remaining
    if (proof.remainingMs > 0) {
      await new Promise((r) => setTimeout(r, proof.remainingMs + 20));
    }

    // 6. Complete escrow recovery to obtain Escrow Share E
    const escrowResult = await this.completeEscrowRecovery(init.requestId);

    // 7. Fetch SP recovery data (includes Share S)
    const spRecoveryData = await this.request(
      'GET',
      `/api/v1/vault/${encodeURIComponent(vaultId)}/recovery-data`
    );

    // 8. Combine SP Share S (id: 2) and Escrow Share E (id: 3)
    return this.recoverVaultFromShares(vaultId, spRecoveryData.spShare, escrowResult.escrowShare);
  }

  /**
   * FORGOT PASSWORD ($U + S$):
   *
   * 1. Fetches SP recovery data { wrappedKeyRec, spShare, vaultCiphertext }.
   * 2. Reconstructs K_rec from User Share U (id: 1) and SP Share S (id: 2).
   * 3. Locally unwraps K_data = unwrapKey(wrappedKeyRec, K_rec).
   * 4. Locally decrypts vaultCiphertext with unwrapped K_data.
   * 5. Derives new K_pw' from newPassword and fresh salt via Argon2id.
   * 6. Re-wraps active K_data under new K_pw' -> newWrappedKeyPw.
   * 7. Updates SP with new salt and newWrappedKeyPw (SP never sees password or K_data).
   * 8. Returns decrypted vault and confirms password reset.
   */
  async forgotPasswordReset(options: {
    vaultId: string;
    userShare: ShamirShare;
    newPassword: string;
  }): Promise<ForgotPasswordResult> {
    const { vaultId, userShare, newPassword } = options;

    if (!userShare || userShare.id !== 1) {
      throw new Error(`Forgot Password requires User Share U (expected share id: 1, got ${userShare?.id}).`);
    }

    // 1. Fetch SP recovery data (includes Share S and W_rec)
    const spRecoveryData = await this.request(
      'GET',
      `/api/v1/vault/${encodeURIComponent(vaultId)}/recovery-data`
    );

    // 2. Reconstruct K_rec from User Share U (1) and SP Share S (2)
    const kRec = reconstructRecoveryKey([userShare, spRecoveryData.spShare]);

    // 3. Locally unwrap K_data
    const dataKey = unwrapKey(spRecoveryData.wrappedKeyRec, kRec);

    // 4. Decrypt vault contents
    const decryptedBytes = decryptVault(spRecoveryData.vaultCiphertext, dataKey);
    const plaintext = new TextDecoder().decode(decryptedBytes);

    // 5. Derive new K_pw' and wrap K_data under new password
    const saltBytes = generateSalt(16);
    const saltHex = Buffer.from(saltBytes).toString('hex');
    const argonParams = this.config.argon2Params || FAST_TEST_ARGON2_PARAMS;
    const newKPw = derivePasswordKey(newPassword, saltBytes, argonParams);
    const newWrappedKeyPw = wrapKey(dataKey, newKPw);

    // 6. Transmit new password wrapper to SP
    await this.request(
      'POST',
      `/api/v1/vault/${encodeURIComponent(vaultId)}/reset-password`,
      {
        salt: saltHex,
        wrappedKeyPw: newWrappedKeyPw,
      }
    );

    return {
      vaultId,
      dataKey,
      plaintext,
      plaintextBytes: decryptedBytes,
      salt: saltHex,
      passwordReset: true,
    };
  }

  /**
   * ALGORITHM 2: $U + E$ Recovery with Schnorr Challenge-Response & Automatic Key Rotation
   *
   * 1. Uses User Share U (id: 1) and initiates Escrow recovery for Share E (id: 3).
   * 2. Escrow Coordinator generates Schnorr challenge.
   * 3. Client proves identity via Schnorr signature using client's private key (sk_rec) + Aadhaar OTP.
   * 4. Delay timer runs.
   * 5. Escrow nodes release sub-shares and coordinator reconstructs Escrow Share E.
   * 6. Client fetches W_rec and vaultCiphertext from SP.
   * 7. Client reconstructs K_rec from U + E, unwraps K_data, and decrypts vault payload.
   *
   * AUTOMATIC KEY ROTATION (Steps 8 & 9):
   * 8. Step 8: Generates fresh K_rec', re-wraps K_data under K_rec' -> W_rec',
   *    and splits K_rec' into fresh shares U', S', E'.
   * 9. Step 9: Revokes old shares on SP and Escrow:
   *    - Overwrites old Share S and W_rec with S' and W_rec' on SP (logged to SP Audit Log).
   *    - Replaces E on Escrow Cluster; nodes N1, N2, N3 revoke old sub-shares and store N1', N2', N3'
   *      (logged to Escrow Audit Log with signed Merkle root checkpoint).
   * 10. Returns decrypted vault along with fresh User Share U' for client persistent storage.
   */
  async recoverVaultAlgorithm2(options: {
    vaultId: string;
    userShare: ShamirShare;
    clientPrivateKey: Uint8Array | string;
    otp?: string;
    otpProvider?: (init: RecoveryInitiationResult) => Promise<string> | string;
    initSession?: RecoveryInitiationResult;
    customDelayMs?: number;
    rotateClientKeys?: boolean;
  }): Promise<Algorithm2RecoveryResult> {
    const { vaultId, userShare, clientPrivateKey, customDelayMs, rotateClientKeys } = options;

    if (!userShare || userShare.id !== 1) {
      throw new Error(`Algorithm 2 requires User Share U (expected share id: 1, got ${userShare?.id}).`);
    }

    // 1. Initiate escrow recovery session for U+E
    const init = options.initSession || (await this.initiateEscrowRecovery(vaultId, 'U_PLUS_E'));

    // 2. Resolve OTP
    const otp = options.otpProvider ? await options.otpProvider(init) : options.otp;
    if (!otp) {
      throw new Error('Aadhaar OTP is required for recovery (provide otp or otpProvider).');
    }

    // 3. Sign Schnorr challenge
    const signature = signSchnorrChallenge(init.challenge, clientPrivateKey);

    // 4. Submit multi-factor proof to Escrow Coordinator
    const proof = await this.submitEscrowRecoveryProof(
      init.requestId,
      signature,
      otp,
      customDelayMs
    );

    // 5. Wait for timelock delay if remaining
    if (proof.remainingMs > 0) {
      await new Promise((r) => setTimeout(r, proof.remainingMs + 20));
    }

    // 6. Complete escrow recovery to obtain Escrow Share E (id: 3)
    const escrowResult = await this.completeEscrowRecovery(init.requestId);

    // 7. Fetch SP recovery data (W_rec and vaultCiphertext)
    const spRecoveryData = await this.request(
      'GET',
      `/api/v1/vault/${encodeURIComponent(vaultId)}/recovery-data`
    );

    // Combine User Share U (id: 1) and Escrow Share E (id: 3) to reconstruct K_rec
    const kRec = reconstructRecoveryKey([userShare, escrowResult.escrowShare]);
    const dataKey = unwrapKey(spRecoveryData.wrappedKeyRec, kRec);
    const decryptedBytes = decryptVault(spRecoveryData.vaultCiphertext, dataKey);
    const plaintext = new TextDecoder().decode(decryptedBytes);

    // =========================================================================
    // STEP 8: Generate Fresh K_rec' and Split Fresh U', S', E' Shares
    // =========================================================================
    const freshKRec = generateDataKey();
    const freshWrappedKeyRec = wrapKey(dataKey, freshKRec);
    const { userShare: freshU, spShare: freshS, escrowShare: freshE } = splitRecoveryKey(freshKRec);

    let freshSchnorrKeys: SchnorrKeyPair | undefined;
    if (rotateClientKeys) {
      freshSchnorrKeys = generateSchnorrKeyPair();
    }

    // =========================================================================
    // STEP 9: Revoke Old Shares on SP and Escrow & Record Audit Log
    // =========================================================================
    // 9a. Revoke old Share S and update W_rec' on Service Provider
    await this.request(
      'POST',
      `/api/v1/vault/${encodeURIComponent(vaultId)}/rotate-recovery-key`,
      {
        wrappedKeyRec: freshWrappedKeyRec,
        spShare: freshS,
      }
    );

    // 9b. Revoke old sub-shares on Escrow Nodes and partition fresh E' across N1, N2, N3
    const escrowRotate = await this.request(
      'POST',
      '/api/v1/escrow/rotate',
      {
        vaultId,
        newEscrowShareE: freshE,
        newClientPubKeyHex: freshSchnorrKeys?.publicKeyHex,
      },
      this.config.escrowUrl
    );

    return {
      vaultId,
      dataKey,
      plaintext,
      plaintextBytes: decryptedBytes,
      sharesUsed: {
        share1Id: 1, // User Share U
        share2Id: 3, // Escrow Share E
      },
      rotated: true,
      newUserShare: freshU,
      newEscrowShare: freshE,
      newSchnorrKeys: freshSchnorrKeys,
      escrowCheckpoint: escrowRotate.checkpoint,
    };
  }

  /**
   * ALGORITHM 4: Total Loss Recovery ($S + E$) & Strict Mode Enforcement
   *
   * Scenario: User lost both daily password and local User Share U (Total Device Loss).
   *
   * STRICT MODE ENFORCEMENT:
   * If the vault was configured in 'STRICT' mode, Total Loss S+E recovery is strictly forbidden.
   * Both the Service Provider and Escrow Policy Engine reject the request.
   *
   * RECOVERABLE MODE:
   * 1. Fetches SP recovery data with S_PLUS_E mode flag.
   * 2. Initiates Escrow recovery with recoveryType: 'S_PLUS_E'.
   * 3. Proves identity via Schnorr signature + Aadhaar OTP.
   * 4. Delay timer runs (timelock allows cancellation if illegitimate).
   * 5. Escrow nodes release sub-shares and reconstruct Escrow Share E (id: 3).
   * 6. Combines SP Share S (id: 2) and Escrow Share E (id: 3) to reconstruct K_rec.
   * 7. Locally unwraps K_data = unwrapKey(wrappedKeyRec, K_rec) and decrypts vault ciphertext.
   *
   * STEP 5: AUTOMATIC KEY ROTATION & DEVICE PROVISIONING:
   * - Generates fresh K_rec' and fresh Schnorr keypair for new device.
   * - Wraps K_data under fresh K_rec' -> fresh W_rec'.
   * - Splits K_rec' into fresh U', S', E'.
   * - If newPassword provided: derives new K_pw' and wraps K_data -> new W_pw'.
   * - Revokes old Share S on SP (updates W_rec', S', W_pw', salt).
   * - Revokes old sub-shares on Escrow Nodes (partitions fresh E' -> N1', N2', N3', updates pk_rec).
   * - Returns recovered vault, fresh User Share U', and new Schnorr keypair.
   */
  async recoverVaultAlgorithm4(options: {
    vaultId: string;
    clientPrivateKey: Uint8Array | string;
    otp?: string;
    otpProvider?: (init: RecoveryInitiationResult) => Promise<string> | string;
    initSession?: RecoveryInitiationResult;
    customDelayMs?: number;
    newPassword?: string;
  }): Promise<Algorithm4RecoveryResult> {
    const { vaultId, clientPrivateKey, customDelayMs, newPassword } = options;

    // 1. Check SP recovery data with S_PLUS_E mode flag (throws if vault is in STRICT mode)
    const spRecoveryData = await this.request(
      'GET',
      `/api/v1/vault/${encodeURIComponent(vaultId)}/recovery-data?mode=S_PLUS_E`
    );

    if (spRecoveryData.recoveryMode === 'STRICT') {
      throw new Error(
        `Strict Mode Violation: Vault '${vaultId}' is configured in STRICT mode. Total loss S+E recovery is strictly disabled.`
      );
    }

    // 2. Initiate Escrow recovery session for S_PLUS_E (throws if Escrow finds STRICT mode)
    const init = options.initSession || (await this.initiateEscrowRecovery(vaultId, 'S_PLUS_E'));

    // 3. Resolve OTP
    const otp = options.otpProvider ? await options.otpProvider(init) : options.otp;
    if (!otp) {
      throw new Error('Aadhaar OTP is required for recovery (provide otp or otpProvider).');
    }

    // 4. Sign Schnorr challenge
    const signature = signSchnorrChallenge(init.challenge, clientPrivateKey);

    // 5. Submit multi-factor proof to Escrow
    const proof = await this.submitEscrowRecoveryProof(
      init.requestId,
      signature,
      otp,
      customDelayMs
    );

    // 6. Wait for timelock delay
    if (proof.remainingMs > 0) {
      await new Promise((r) => setTimeout(r, proof.remainingMs + 20));
    }

    // 7. Complete escrow recovery to obtain Escrow Share E (id: 3)
    const escrowResult = await this.completeEscrowRecovery(init.requestId);

    // 8. Combine SP Share S (id: 2) and Escrow Share E (id: 3) to reconstruct K_rec
    const kRec = reconstructRecoveryKey([spRecoveryData.spShare, escrowResult.escrowShare]);
    const dataKey = unwrapKey(spRecoveryData.wrappedKeyRec, kRec);
    const decryptedBytes = decryptVault(spRecoveryData.vaultCiphertext, dataKey);
    const plaintext = new TextDecoder().decode(decryptedBytes);

    // =========================================================================
    // STEP 5 OF ALGORITHM 4: Key Rotation & Device Reset
    // =========================================================================
    // 5a. Generate fresh K_rec' and fresh Schnorr identity keys for new client device
    const freshKRec = generateDataKey();
    const freshWrappedKeyRec = wrapKey(dataKey, freshKRec);
    const { userShare: freshU, spShare: freshS, escrowShare: freshE } = splitRecoveryKey(freshKRec);
    const freshSchnorrKeys = generateSchnorrKeyPair();

    // 5b. If new password provided, derive new K_pw' and wrap K_data
    let newSaltHex: string | undefined;
    let newWrappedKeyPw: any;
    if (newPassword) {
      const saltBytes = generateSalt(16);
      newSaltHex = Buffer.from(saltBytes).toString('hex');
      const argonParams = this.config.argon2Params || FAST_TEST_ARGON2_PARAMS;
      const kPw = derivePasswordKey(newPassword, saltBytes, argonParams);
      newWrappedKeyPw = wrapKey(dataKey, kPw);
    }

    // 5c. Revoke old Share S on SP (updates W_rec', S', and optionally W_pw', salt)
    await this.request(
      'POST',
      `/api/v1/vault/${encodeURIComponent(vaultId)}/rotate-recovery-key`,
      {
        wrappedKeyRec: freshWrappedKeyRec,
        spShare: freshS,
        salt: newSaltHex,
        wrappedKeyPw: newWrappedKeyPw,
      }
    );

    // 5d. Revoke old sub-shares on Escrow Nodes and distribute fresh E'
    const escrowRotate = await this.request(
      'POST',
      '/api/v1/escrow/rotate',
      {
        vaultId,
        newEscrowShareE: freshE,
        newClientPubKeyHex: freshSchnorrKeys.publicKeyHex,
      },
      this.config.escrowUrl
    );

    return {
      vaultId,
      dataKey,
      plaintext,
      plaintextBytes: decryptedBytes,
      sharesUsed: {
        share1Id: 2, // SP Share S
        share2Id: 3, // Escrow Share E
      },
      rotated: true,
      newUserShare: freshU,
      newEscrowShare: freshE,
      newSchnorrKeys: freshSchnorrKeys,
      newSalt: newSaltHex,
      passwordReset: !!newPassword,
      escrowCheckpoint: escrowRotate.checkpoint,
    };
  }
}
