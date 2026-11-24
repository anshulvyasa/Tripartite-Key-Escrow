import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

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
  type ShamirShare,
  type SchnorrKeyPair,
} from '@trivault/crypto-core';
import { VaultStorage } from '@trivault/service-provider';
import { EscrowCoordinator, type NodeId } from '@trivault/escrow-cluster';
import { MockAadhaarService } from '@trivault/mock-aadhaar';
import { verifySignedCheckpoint, MerkleTree } from '@trivault/audit-log';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.resolve(__dirname, '../public');

// =============================================================================
// GLOBAL SIMULATION STATE
// =============================================================================
export class DashboardState {
  public spStorage: VaultStorage;
  public escrowCoordinator: EscrowCoordinator;
  public aadhaarService: MockAadhaarService;

  // Simulator Toggles
  public spOnline: boolean = true;
  public nodesOnline: Record<NodeId, boolean> = { N1: true, N2: true, N3: true };
  public deviceHooks = {
    biometricOk: true,
    registeredDevice: true,
    isNewDevice: false,
  };

  // Tamper State
  public tamperedEvent3: boolean = false;
  public originalEvent3Payload: any = null;

  // Active Recovery Request
  public activeRecoverySession: {
    requestId: string;
    vaultId: string;
    recoveryType: 'U_PLUS_E' | 'S_PLUS_E';
    status: 'PENDING_DELAY' | 'COMPLETED' | 'CANCELLED';
    delayExpiresAt: number;
    delayDurationMs: number;
    createdAt: number;
    reason?: string;
  } | null = null;

  // Local Client State (Simulating Browser LocalStorage & Android KeyStore)
  public clientLocalState: {
    vaultId: string;
    password: string;
    passwordKeyHex: string;
    recoveryMode: 'RECOVERABLE' | 'STRICT';
    dataKeyHex: string;
    recoveryKeyHex: string;
    userShare: ShamirShare | null;
    schnorrKeys: SchnorrKeyPair | null;
    salt: string;
    cachedWrappedKeyPw: any;
    cachedWrappedKeyRec: any;
    cachedCiphertext: any;
    isVaultUnlocked: boolean;
    decryptedItems: Array<{ id: string; title: string; category: string; secret: string }>;
    encryptedItems: Array<{ id: string; title: string; category: string; ciphertextPreview: string }>;
    activeItems: Array<{ id: string; title: string; category: string; secret: string }>;
    lastActionMessage?: string;
  };

  // Master list of configured vault items (persisted across locks/re-seed)
  public currentVaultItems: Array<{ id: string; title: string; category: string; secret: string }> = [
    { id: '1', title: 'Chase Sapphire Banking PIN', category: 'Finance', secret: '8492' },
    { id: '2', title: 'BTC Cold Storage Mnemonic', category: 'Crypto', secret: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' },
    { id: '3', title: 'AWS Production Root Key', category: 'Infrastructure', secret: 'AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' },
    { id: '4', title: 'Bastion SSH Private Key', category: 'DevOps', secret: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBastionProductionAccessKey' },
  ];

  constructor() {
    this.spStorage = new VaultStorage();
    this.aadhaarService = new MockAadhaarService();
    this.aadhaarService.registerProfile({
      aadhaarNumber: '999988887777',
      phoneNumber: '+91-9876543210',
      name: 'Alice Resident',
    });

    this.escrowCoordinator = new EscrowCoordinator({
      aadhaarService: this.aadhaarService,
      policyConfig: { defaultDelayMs: 6000 },
    });

    this.clientLocalState = {
      vaultId: 'vault-demo-001',
      password: 'MasterPassword#2026',
      passwordKeyHex: '',
      recoveryMode: 'RECOVERABLE',
      dataKeyHex: '',
      recoveryKeyHex: '',
      userShare: null,
      schnorrKeys: null,
      salt: '',
      cachedWrappedKeyPw: null,
      cachedWrappedKeyRec: null,
      cachedCiphertext: null,
      isVaultUnlocked: false,
      decryptedItems: [],
      encryptedItems: [],
      activeItems: this.currentVaultItems,
    };

    // Pre-populate realistic seed vault
    this.seedDemoVault();
  }

  /**
   * Seeds demo vault with sample or custom encrypted credentials.
   */
  public seedDemoVault(
    customVaultId?: string,
    customPassword?: string,
    customItems?: Array<{ id: string; title: string; category: string; secret: string }>,
    customMode?: 'RECOVERABLE' | 'STRICT',
    unlockVault: boolean = false
  ): void {
    const vaultId = customVaultId || this.clientLocalState?.vaultId || 'vault-demo-001';
    const password = customPassword || this.clientLocalState?.password || 'MasterPassword#2026';
    const recoveryMode = customMode || this.clientLocalState?.recoveryMode || 'RECOVERABLE';

    if (customItems !== undefined) {
      this.currentVaultItems = customItems;
    }

    const sampleItems = this.currentVaultItems;

    // 1. Generate local K_data
    const dataKey = generateDataKey();
    const dataKeyHex = Buffer.from(dataKey).toString('hex');

    // 2. Generate salt & K_pw
    const saltBytes = generateSalt(16);
    const saltHex = Buffer.from(saltBytes).toString('hex');
    const kPw = derivePasswordKey(password, saltBytes, FAST_TEST_ARGON2_PARAMS);
    const wrappedKeyPw = wrapKey(dataKey, kPw);

    // 3. Generate K_rec & wrap K_data
    const kRec = generateDataKey();
    const kRecHex = Buffer.from(kRec).toString('hex');
    const wrappedKeyRec = wrapKey(dataKey, kRec);

    // 4. Split K_rec 2-of-3 into U, S, E
    const { userShare, spShare, escrowShare } = splitRecoveryKey(kRec);

    // 5. Generate client Schnorr recovery keypair
    const schnorrKeys = generateSchnorrKeyPair();

    // 6. Encrypt sample items
    const rawPlaintext = JSON.stringify(sampleItems);
    const vaultCiphertext = encryptVault(rawPlaintext, dataKey);

    // 7. Store on SP
    if (this.spStorage.hasVault(vaultId)) {
      (this.spStorage as any).vaults.delete(vaultId);
    }
    this.spStorage.createVault({
      vaultId,
      salt: saltHex,
      wrappedKeyPw,
      wrappedKeyRec,
      spShare,
      vaultCiphertext,
      recoveryMode,
    });

    // 8. Register on Escrow Cluster
    if ((this.escrowCoordinator as any).vaults.has(vaultId)) {
      (this.escrowCoordinator as any).vaults.delete(vaultId);
    }
    this.escrowCoordinator.registerVault(
      vaultId,
      escrowShare,
      schnorrKeys.publicKeyHex,
      '999988887777',
      recoveryMode
    );

    // 9. Client local state (Initially in LOCKED / ENCRYPTED state)
    const encryptedItems = sampleItems.map((item, idx) => ({
      id: item.id,
      title: item.title,
      category: item.category,
      ciphertextPreview: `AES-GCM::${vaultCiphertext.ciphertext.slice(idx * 20, (idx + 1) * 20)}...::tag=${vaultCiphertext.tag.slice(0, 8)}`,
    }));

    this.clientLocalState = {
      vaultId,
      password,
      passwordKeyHex: Buffer.from(kPw).toString('hex'),
      recoveryMode,
      dataKeyHex,
      recoveryKeyHex: kRecHex,
      userShare,
      schnorrKeys,
      salt: saltHex,
      cachedWrappedKeyPw: wrappedKeyPw,
      cachedWrappedKeyRec: wrappedKeyRec,
      cachedCiphertext: vaultCiphertext,
      isVaultUnlocked: unlockVault,
      decryptedItems: unlockVault ? sampleItems : [],
      encryptedItems,
      activeItems: sampleItems,
      lastActionMessage: unlockVault
        ? 'Vault initialized with Algorithm 1 (Setup Vault). Status: UNLOCKED. Plaintext secrets are visible below.'
        : 'Vault initialized with Algorithm 1 (Setup Vault). Status: LOCKED (Encrypted). Click "Decrypt Vault" to decrypt with K_data.',
    };
  }
}

// =============================================================================
// HTTP SERVER IMPLEMENTATION
// =============================================================================
export class DashboardServer {
  public readonly state: DashboardState;
  private server: http.Server | null = null;

  constructor(state?: DashboardState) {
    this.state = state || new DashboardState();
  }

  private handleApi = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
    const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;
    const method = req.method?.toUpperCase();

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const readJson = async (): Promise<any> => {
      let body = '';
      for await (const chunk of req) {
        body += chunk;
      }
      return body ? JSON.parse(body) : {};
    };

    try {
      // -----------------------------------------------------------------------
      // 1. GET /api/state — Complete live status snapshot
      // -----------------------------------------------------------------------
      if (pathname === '/api/state' && method === 'GET') {
        const vaultId = this.state.clientLocalState.vaultId;

        // Service Provider State
        let spRecord: any = null;
        if (this.state.spStorage.hasVault(vaultId)) {
          const rec = this.state.spStorage.getRecoveryData(vaultId);
          const login = this.state.spStorage.getLoginData(vaultId);
          spRecord = {
            vaultId: rec.vaultId,
            recoveryMode: rec.recoveryMode,
            salt: login.salt,
            wrappedKeyPw: login.wrappedKeyPw,
            wrappedKeyRec: rec.wrappedKeyRec,
            spShare: rec.spShare,
            ciphertextPreview: login.vaultCiphertext.ciphertext.slice(0, 32) + '...',
            fullCiphertext: login.vaultCiphertext,
          };
        }

        // Escrow Nodes status
        const nodes = {
          N1: {
            id: 'N1',
            online: this.state.nodesOnline.N1,
            hasShare: this.state.escrowCoordinator.nodeN1.hasSubShare(vaultId),
            subShareId: 1,
          },
          N2: {
            id: 'N2',
            online: this.state.nodesOnline.N2,
            hasShare: this.state.escrowCoordinator.nodeN2.hasSubShare(vaultId),
            subShareId: 2,
          },
          N3: {
            id: 'N3',
            online: this.state.nodesOnline.N3,
            hasShare: this.state.escrowCoordinator.nodeN3.hasSubShare(vaultId),
            subShareId: 3,
          },
        };

        const onlineNodesCount = Object.values(this.state.nodesOnline).filter(Boolean).length;

        // Audit Logs
        const spAuditEvents = this.state.spStorage.auditLog.getEvents();
        const escrowAuditEvents = this.state.escrowCoordinator.auditLog.getEvents();
        const escrowChainCheck = this.state.escrowCoordinator.auditLog.verifyChainIntegrity();
        const latestCheckpoint = this.state.escrowCoordinator.latestCheckpoint;

        let checkpointValid = false;
        if (latestCheckpoint) {
          try {
            checkpointValid = verifySignedCheckpoint(latestCheckpoint);
          } catch {
            checkpointValid = false;
          }
        }

        res.writeHead(200);
        res.end(
          JSON.stringify({
            client: {
              ...this.state.clientLocalState,
              deviceHooks: this.state.deviceHooks,
              activeRecoverySession: this.state.activeRecoverySession,
            },
            serviceProvider: {
              isOnline: this.state.spOnline,
              record: spRecord,
              totalVaults: this.state.spStorage.count,
              auditEvents: spAuditEvents,
            },
            escrowCluster: {
              nodes,
              onlineCount: onlineNodesCount,
              thresholdRequired: 2,
              coordinatorPubKeyHex: this.state.escrowCoordinator.coordinatorKeys.publicKeyHex,
              auditEvents: escrowAuditEvents,
              chainIntegrity: escrowChainCheck,
              latestCheckpoint,
              checkpointValid,
            },
            auditVerification: {
              chainValid: escrowChainCheck.valid,
              brokenAtIndex: escrowChainCheck.brokenIndex,
              tamperedEvent3: this.state.tamperedEvent3,
              checkpointValid,
            },
          })
        );
        return;
      }

      // -----------------------------------------------------------------------
      // 2. POST /api/sp/toggle-offline
      // -----------------------------------------------------------------------
      if (pathname === '/api/sp/toggle-offline' && method === 'POST') {
        this.state.spOnline = !this.state.spOnline;
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, spOnline: this.state.spOnline }));
        return;
      }

      // -----------------------------------------------------------------------
      // 3. POST /api/escrow/toggle-node
      // -----------------------------------------------------------------------
      if (pathname === '/api/escrow/toggle-node' && method === 'POST') {
        const { nodeId } = await readJson();
        if (nodeId in this.state.nodesOnline) {
          const id = nodeId as NodeId;
          this.state.nodesOnline[id] = !this.state.nodesOnline[id];
        }
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, nodesOnline: this.state.nodesOnline }));
        return;
      }

      // -----------------------------------------------------------------------
      // 4. POST /api/client/device-hooks
      // -----------------------------------------------------------------------
      if (pathname === '/api/client/device-hooks' && method === 'POST') {
        const payload = await readJson();
        this.state.deviceHooks = {
          ...this.state.deviceHooks,
          ...payload,
        };
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, deviceHooks: this.state.deviceHooks }));
        return;
      }

      // -----------------------------------------------------------------------
      // 5. POST /api/client/vault-mode
      // -----------------------------------------------------------------------
      if (pathname === '/api/client/vault-mode' && method === 'POST') {
        const { recoveryMode } = await readJson();
        this.state.clientLocalState.recoveryMode = recoveryMode;
        // Re-seed vault with new mode
        this.state.seedDemoVault();
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, recoveryMode }));
        return;
      }

      // -----------------------------------------------------------------------
      // 6. POST /api/vault/setup (Algorithm 1)
      // -----------------------------------------------------------------------
      if (pathname === '/api/vault/setup' && method === 'POST') {
        const { vaultId, password, items, recoveryMode, expectedVaultIv } = await readJson();
        if (
          (vaultId !== undefined && (typeof vaultId !== 'string' || !vaultId.trim())) ||
          (password !== undefined && (typeof password !== 'string' || !password.length)) ||
          (recoveryMode !== undefined && recoveryMode !== 'RECOVERABLE' && recoveryMode !== 'STRICT') ||
          (expectedVaultIv !== undefined && expectedVaultIv !== null && typeof expectedVaultIv !== 'string') ||
          (items !== undefined && (!Array.isArray(items) || items.some((item) =>
            !item || ['id', 'title', 'category', 'secret'].some((field) => typeof item[field] !== 'string')
          )))
        ) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'Provide a valid vault ID, password, recovery mode, and secret entries.' }));
          return;
        }
        const vId = vaultId || 'vault-demo-001';
        const pw = password || 'MasterPassword#2026';
        const mode = recoveryMode || 'RECOVERABLE';
        if (vId === this.state.clientLocalState.vaultId && !this.state.clientLocalState.dataKeyHex) {
          res.writeHead(409);
          res.end(JSON.stringify({ error: 'Recover the data key or log in before replacing this vault.' }));
          return;
        }
        if (expectedVaultIv !== undefined) {
          const currentIv = this.state.spStorage.hasVault(vId)
            ? this.state.spStorage.getLoginData(vId).vaultCiphertext.iv
            : null;
          if (currentIv !== expectedVaultIv) {
            res.writeHead(409);
            res.end(JSON.stringify({ error: 'The vault changed while this form was open. Copy your new entries, then reopen Manage Secrets to load the current vault.' }));
            return;
          }
        }
        this.state.seedDemoVault(vId, pw, items, mode, true);
        res.writeHead(200);
        res.end(
          JSON.stringify({
            success: true,
            vaultId: vId,
            itemCount: this.state.currentVaultItems.length,
            items: this.state.currentVaultItems,
          })
        );
        return;
      }

      // -----------------------------------------------------------------------
      // 7. POST /api/vault/login (Algorithm 3)
      // -----------------------------------------------------------------------
      if (pathname === '/api/vault/login' && method === 'POST') {
        if (!this.state.spOnline) {
          res.writeHead(503);
          res.end(JSON.stringify({ error: 'Service Provider is OFFLINE. Cannot perform daily password login.' }));
          return;
        }

        const body = await readJson();
        const password = body.password;
        const autoDecrypt = body.autoDecrypt === true;
        const vaultId = this.state.clientLocalState.vaultId;
        const loginData = this.state.spStorage.getLoginData(vaultId);

        // Derive K_pw
        const saltBytes = Buffer.from(loginData.salt, 'hex');
        const kPw = derivePasswordKey(password, saltBytes, FAST_TEST_ARGON2_PARAMS);

        // Unwrap K_data (throws if wrong password!)
        let dataKey: Uint8Array;
        try {
          dataKey = unwrapKey(loginData.wrappedKeyPw, kPw);
        } catch {
          // Keep vault locked on tag failure
          this.state.clientLocalState.isVaultUnlocked = false;
          this.state.clientLocalState.decryptedItems = [];
          res.writeHead(401);
          res.end(
            JSON.stringify({
              error: 'AES-GCM Authentication Tag Failure: Wrong password! Tag check failed when unwrapping K_data.',
            })
          );
          return;
        }

        // Successfully unwrapped K_data
        const dataKeyHex = Buffer.from(dataKey).toString('hex');
        this.state.clientLocalState.dataKeyHex = dataKeyHex;
        this.state.clientLocalState.password = password;
        this.state.clientLocalState.passwordKeyHex = Buffer.from(kPw).toString('hex');

        // Decrypt vault items
        const decryptedBytes = decryptVault(loginData.vaultCiphertext, dataKey);
        const decryptedItems = JSON.parse(new TextDecoder().decode(decryptedBytes));
        this.state.currentVaultItems = decryptedItems;
        this.state.clientLocalState.activeItems = decryptedItems;

        if (autoDecrypt) {
          this.state.clientLocalState.isVaultUnlocked = true;
          this.state.clientLocalState.decryptedItems = decryptedItems;
          this.state.clientLocalState.lastActionMessage =
            'Algorithm 3 Normal Login succeeded! Vault unlocked & decrypted locally.';
        } else {
          this.state.clientLocalState.isVaultUnlocked = false;
          this.state.clientLocalState.decryptedItems = [];
          this.state.clientLocalState.lastActionMessage =
            '✅ Algorithm 3 Login succeeded! K_data unwrapped in client memory. Click "Decrypt Vault" to reveal plaintext.';
        }

        res.writeHead(200);
        res.end(JSON.stringify({
          success: true,
          decryptedItems,
          isVaultUnlocked: this.state.clientLocalState.isVaultUnlocked,
          dataKeyHex,
        }));
        return;
      }

      // -----------------------------------------------------------------------
      // 7B. POST /api/vault/decrypt (Manual Decrypt Button)
      // -----------------------------------------------------------------------
      if (pathname === '/api/vault/decrypt' && method === 'POST') {
        const dataKeyHex = this.state.clientLocalState.dataKeyHex;
        if (!dataKeyHex) {
          res.writeHead(400);
          res.end(
            JSON.stringify({
              error: 'Cannot decrypt: Data Key (K_data) is not loaded in client memory. Please authenticate via Algorithm 3 (Login) or perform recovery first.',
            })
          );
          return;
        }

        const ciphertext = this.state.clientLocalState.cachedCiphertext;
        if (!ciphertext) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'No vault ciphertext available to decrypt.' }));
          return;
        }

        try {
          const dataKey = Buffer.from(dataKeyHex, 'hex');
          const decryptedBytes = decryptVault(ciphertext, dataKey);
          const decryptedItems = JSON.parse(new TextDecoder().decode(decryptedBytes));
          this.state.currentVaultItems = decryptedItems;
          this.state.clientLocalState.activeItems = decryptedItems;
          this.state.clientLocalState.isVaultUnlocked = true;
          this.state.clientLocalState.decryptedItems = decryptedItems;
          this.state.clientLocalState.lastActionMessage =
            '🔓 Vault decrypted successfully using locally held Data Key (K_data)!';

          res.writeHead(200);
          res.end(JSON.stringify({ success: true, isVaultUnlocked: true, decryptedItems }));
          return;
        } catch (err: any) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: `Decryption failed: ${err.message}` }));
          return;
        }
      }

      // -----------------------------------------------------------------------
      // 7C. POST /api/vault/lock (Manual Lock Button)
      // -----------------------------------------------------------------------
      if (pathname === '/api/vault/lock' && method === 'POST') {
        const body = await readJson().catch(() => ({}));
        const purgeKey = body && body.purgeKey === true;
        this.state.clientLocalState.isVaultUnlocked = false;
        this.state.clientLocalState.decryptedItems = [];
        if (purgeKey) {
          this.state.clientLocalState.dataKeyHex = '';
          this.state.clientLocalState.passwordKeyHex = '';
          this.state.clientLocalState.recoveryKeyHex = '';
          this.state.clientLocalState.password = '';
          this.state.clientLocalState.activeItems = [];
          this.state.currentVaultItems = [];
          this.state.clientLocalState.lastActionMessage =
            'Key loss simulated. Loaded encryption keys, cached password and plaintext cleared. Recover K_data with Algorithm 2 or log in with your password.';
        } else {
          this.state.clientLocalState.lastActionMessage =
            '🔒 Vault locked. Plaintext wiped from memory. Data Key (K_data) retained in client keystore; click "Decrypt Vault" to reveal.';
        }

        res.writeHead(200);
        res.end(JSON.stringify({ success: true, isVaultUnlocked: false, keyRetained: !purgeKey }));
        return;
      }

      // -----------------------------------------------------------------------
      // 8. POST /api/vault/forgot-password (U + S)
      // -----------------------------------------------------------------------
      if (pathname === '/api/vault/forgot-password' && method === 'POST') {
        if (!this.state.spOnline) {
          res.writeHead(503);
          res.end(JSON.stringify({ error: 'Service Provider is OFFLINE. Cannot retrieve Share S for password reset.' }));
          return;
        }

        const { newPassword } = await readJson();
        const vaultId = this.state.clientLocalState.vaultId;
        const userShare = this.state.clientLocalState.userShare;

        if (!userShare) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'Missing local User Share U.' }));
          return;
        }

        const spData = this.state.spStorage.getRecoveryData(vaultId);
        const kRec = reconstructRecoveryKey([userShare, spData.spShare]);
        const dataKey = unwrapKey(spData.wrappedKeyRec, kRec);
        const items = JSON.parse(new TextDecoder().decode(decryptVault(spData.vaultCiphertext, dataKey)));

        // Derive new password wrapper
        const saltBytes = generateSalt(16);
        const saltHex = Buffer.from(saltBytes).toString('hex');
        const newKPw = derivePasswordKey(newPassword, saltBytes, FAST_TEST_ARGON2_PARAMS);
        const newWrappedKeyPw = wrapKey(dataKey, newKPw);

        this.state.spStorage.resetPassword(vaultId, saltHex, newWrappedKeyPw);
        this.state.clientLocalState.password = newPassword;
        this.state.clientLocalState.passwordKeyHex = Buffer.from(newKPw).toString('hex');
        this.state.clientLocalState.salt = saltHex;
        this.state.clientLocalState.dataKeyHex = Buffer.from(dataKey).toString('hex');
        this.state.currentVaultItems = items;
        this.state.clientLocalState.activeItems = items;
        this.state.clientLocalState.isVaultUnlocked = false;
        this.state.clientLocalState.decryptedItems = [];
        this.state.clientLocalState.lastActionMessage =
          'Forgot Password (U + S) succeeded! Master password reset and K_data reconstructed. Click "Decrypt Vault" to reveal plaintext.';

        res.writeHead(200);
        res.end(JSON.stringify({ success: true, newPassword, dataKeyHex: this.state.clientLocalState.dataKeyHex }));
        return;
      }

      // -----------------------------------------------------------------------
      // 9. POST /api/vault/recover-algo2 (Algorithm 2: U + E with Schnorr)
      // -----------------------------------------------------------------------
      if (pathname === '/api/vault/recover-algo2' && method === 'POST') {
        const vaultId = this.state.clientLocalState.vaultId;

        // 1. Hardware checks
        if (!this.state.deviceHooks.biometricOk) {
          res.writeHead(403);
          res.end(JSON.stringify({ error: 'Policy Engine Denied: Biometric verification failed.' }));
          return;
        }
        if (!this.state.deviceHooks.registeredDevice) {
          res.writeHead(403);
          res.end(JSON.stringify({ error: 'Policy Engine Denied: Unrecognized device hardware ID.' }));
          return;
        }

        // 2. Online nodes check
        const onlineCount = Object.values(this.state.nodesOnline).filter(Boolean).length;
        if (onlineCount < 2) {
          res.writeHead(400);
          res.end(
            JSON.stringify({
              error: `Escrow Cluster Fault: Only ${onlineCount} node online. 2-of-3 threshold is required!`,
            })
          );
          return;
        }

        // 3. Initiate recovery
        const init = this.state.escrowCoordinator.initiateRecovery(vaultId, 'U_PLUS_E');

        // 4. Sign Schnorr challenge
        const schnorrKeys = this.state.clientLocalState.schnorrKeys!;
        const signature = signSchnorrChallenge(init.challenge, schnorrKeys.privateKey);

        // 5. Submit proof with configurable delay
        const { delayMs } = await readJson();
        const duration = delayMs !== undefined ? delayMs : 5000;
        const proof = this.state.escrowCoordinator.submitRecoveryProof(
          init.requestId,
          signature,
          init.mockOtp!,
          duration
        );

        this.state.activeRecoverySession = {
          requestId: init.requestId,
          vaultId,
          recoveryType: 'U_PLUS_E',
          status: 'PENDING_DELAY',
          delayExpiresAt: proof.delayExpiresAt,
          delayDurationMs: duration,
          createdAt: Date.now(),
        };

        res.writeHead(200);
        res.end(JSON.stringify({ success: true, session: this.state.activeRecoverySession }));
        return;
      }

      // -----------------------------------------------------------------------
      // 10. POST /api/vault/recover-algo4 (Algorithm 4: S + E Total Loss)
      // -----------------------------------------------------------------------
      if (pathname === '/api/vault/recover-algo4' && method === 'POST') {
        const vaultId = this.state.clientLocalState.vaultId;

        // STRICT MODE CHECK
        if (this.state.clientLocalState.recoveryMode === 'STRICT') {
          res.writeHead(403);
          res.end(
            JSON.stringify({
              error: 'Strict Mode Violation: Vault is configured in STRICT mode. S+E total loss recovery is strictly disabled to prevent collusion.',
            })
          );
          return;
        }

        // Check SP
        if (!this.state.spOnline) {
          res.writeHead(503);
          res.end(JSON.stringify({ error: 'Service Provider is OFFLINE. Cannot retrieve Share S for S+E recovery.' }));
          return;
        }

        // Check Escrow nodes threshold
        const onlineCount = Object.values(this.state.nodesOnline).filter(Boolean).length;
        if (onlineCount < 2) {
          res.writeHead(400);
          res.end(
            JSON.stringify({
              error: `Escrow Cluster Fault: Only ${onlineCount} node online. 2-of-3 threshold is required!`,
            })
          );
          return;
        }

        // Initiate recovery
        const init = this.state.escrowCoordinator.initiateRecovery(vaultId, 'S_PLUS_E');
        const schnorrKeys = this.state.clientLocalState.schnorrKeys!;
        const signature = signSchnorrChallenge(init.challenge, schnorrKeys.privateKey);

        // Longest delay (8s) for Algorithm 4 or custom delay
        const { delayMs } = await readJson();
        const duration = delayMs !== undefined ? delayMs : 8000;
        const proof = this.state.escrowCoordinator.submitRecoveryProof(
          init.requestId,
          signature,
          init.mockOtp!,
          duration
        );

        this.state.activeRecoverySession = {
          requestId: init.requestId,
          vaultId,
          recoveryType: 'S_PLUS_E',
          status: 'PENDING_DELAY',
          delayExpiresAt: proof.delayExpiresAt,
          delayDurationMs: duration,
          createdAt: Date.now(),
        };

        res.writeHead(200);
        res.end(JSON.stringify({ success: true, session: this.state.activeRecoverySession }));
        return;
      }

      // -----------------------------------------------------------------------
      // 11. POST /api/vault/complete-recovery
      // -----------------------------------------------------------------------
      if (pathname === '/api/vault/complete-recovery' && method === 'POST') {
        const session = this.state.activeRecoverySession;
        if (!session) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'No active recovery session.' }));
          return;
        }

        // Determine available node pair
        const availableNodes = (['N1', 'N2', 'N3'] as NodeId[]).filter((id) => this.state.nodesOnline[id]);
        if (availableNodes.length < 2) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'Cannot complete: less than 2 escrow nodes are online.' }));
          return;
        }
        const nodePair: [NodeId, NodeId] = [availableNodes[0], availableNodes[1]];

        // Complete escrow release
        const escrowResult = this.state.escrowCoordinator.completeRecovery(session.requestId, nodePair);
        const escrowShareE = escrowResult.escrowShare;

        const vaultId = session.vaultId;
        let dataKey: Uint8Array;
        let decryptedBytes: Uint8Array;

        if (session.recoveryType === 'U_PLUS_E') {
          // Algorithm 2: U + E
          const userShare = this.state.clientLocalState.userShare!;
          const kRec = reconstructRecoveryKey([userShare, escrowShareE]);

          // Can unwrap from local cache or SP
          const wrappedRec = this.state.clientLocalState.cachedWrappedKeyRec;
          const ciphertext = this.state.clientLocalState.cachedCiphertext;
          dataKey = unwrapKey(wrappedRec, kRec);
          decryptedBytes = decryptVault(ciphertext, dataKey);

          // Steps 8 & 9 Key Rotation
          const freshKRec = generateDataKey();
          const freshWrappedRec = wrapKey(dataKey, freshKRec);
          const { userShare: freshU, spShare: freshS, escrowShare: freshE } = splitRecoveryKey(freshKRec);

          if (this.state.spOnline) {
            this.state.spStorage.rotateRecoveryKey(vaultId, freshWrappedRec, freshS);
          }
          this.state.escrowCoordinator.rotateVaultEscrow(vaultId, freshE);

          this.state.clientLocalState.userShare = freshU;
          this.state.clientLocalState.dataKeyHex = Buffer.from(dataKey).toString('hex');
          this.state.clientLocalState.recoveryKeyHex = Buffer.from(freshKRec).toString('hex');
          this.state.clientLocalState.cachedWrappedKeyRec = freshWrappedRec;
          this.state.clientLocalState.lastActionMessage =
            'Algorithm 2 Recovery completed! Keys automatically rotated (Steps 8 & 9). Click "Decrypt Vault" to reveal plaintext.';
        } else {
          // Algorithm 4: S + E
          const spData = this.state.spStorage.getRecoveryData(vaultId);
          const kRec = reconstructRecoveryKey([spData.spShare, escrowShareE]);
          dataKey = unwrapKey(spData.wrappedKeyRec, kRec);
          decryptedBytes = decryptVault(spData.vaultCiphertext, dataKey);

          // Step 5 Key Rotation & Device Reset
          const freshKRec = generateDataKey();
          const freshWrappedRec = wrapKey(dataKey, freshKRec);
          const { userShare: freshU, spShare: freshS, escrowShare: freshE } = splitRecoveryKey(freshKRec);
          const freshSchnorrKeys = generateSchnorrKeyPair();

          this.state.spStorage.rotateRecoveryKey(vaultId, freshWrappedRec, freshS);
          this.state.escrowCoordinator.rotateVaultEscrow(vaultId, freshE, freshSchnorrKeys.publicKeyHex);

          this.state.clientLocalState.userShare = freshU;
          this.state.clientLocalState.schnorrKeys = freshSchnorrKeys;
          this.state.clientLocalState.dataKeyHex = Buffer.from(dataKey).toString('hex');
          this.state.clientLocalState.recoveryKeyHex = Buffer.from(freshKRec).toString('hex');
          this.state.clientLocalState.cachedWrappedKeyRec = freshWrappedRec;
          this.state.clientLocalState.lastActionMessage =
            'Algorithm 4 Total Loss Recovery completed! New device provisioned (Step 5). Click "Decrypt Vault" to reveal plaintext.';
        }

        const items = JSON.parse(new TextDecoder().decode(decryptedBytes));
        this.state.currentVaultItems = items;
        this.state.clientLocalState.activeItems = items;
        this.state.clientLocalState.isVaultUnlocked = false;
        this.state.clientLocalState.decryptedItems = [];
        this.state.activeRecoverySession = null;

        res.writeHead(200);
        res.end(JSON.stringify({
          success: true,
          items,
          isVaultUnlocked: false,
          dataKeyHex: this.state.clientLocalState.dataKeyHex,
        }));
        return;
      }

      // -----------------------------------------------------------------------
      // 12. POST /api/vault/cancel-recovery (SIM-Swap defense)
      // -----------------------------------------------------------------------
      if (pathname === '/api/vault/cancel-recovery' && method === 'POST') {
        const session = this.state.activeRecoverySession;
        if (!session) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'No active recovery session to cancel.' }));
          return;
        }

        this.state.escrowCoordinator.cancelRecovery(
          session.requestId,
          'Fraudulent SIM-swap / unauthorized device detected by owner'
        );
        this.state.activeRecoverySession = null;
        this.state.clientLocalState.lastActionMessage =
          '🚨 Unauthorized recovery cancelled by user! Emergency alert triggered signed audit checkpoint.';

        res.writeHead(200);
        res.end(JSON.stringify({ success: true, cancelled: true }));
        return;
      }

      // -----------------------------------------------------------------------
      // 13. POST /api/audit/tamper-event3
      // -----------------------------------------------------------------------
      if (pathname === '/api/audit/tamper-event3' && method === 'POST') {
        const events = this.state.escrowCoordinator.auditLog.getEvents();
        if (events.length > 2) {
          if (!this.state.originalEvent3Payload) {
            this.state.originalEvent3Payload = JSON.parse(JSON.stringify(events[2].payload));
          }
          // Mutate payload without re-hashing or re-signing
          (events[2] as any).payload = {
            ...events[2].payload,
            tampered: true,
            adversarialInjection: '0xDEADBEEF_UNAUTHORIZED_OVERRIDE',
          };
          this.state.tamperedEvent3 = true;
        }

        res.writeHead(200);
        res.end(JSON.stringify({ success: true, tampered: true }));
        return;
      }

      // -----------------------------------------------------------------------
      // 14. POST /api/audit/restore
      // -----------------------------------------------------------------------
      if (pathname === '/api/audit/restore' && method === 'POST') {
        const events = this.state.escrowCoordinator.auditLog.getEvents();
        if (events.length > 2 && this.state.originalEvent3Payload) {
          (events[2] as any).payload = this.state.originalEvent3Payload;
          this.state.tamperedEvent3 = false;
        }
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, tampered: false }));
        return;
      }

      // -----------------------------------------------------------------------
      // 15. GET /api/audit/merkle-proof
      // -----------------------------------------------------------------------
      if (pathname === '/api/audit/merkle-proof' && method === 'GET') {
        const idx = parseInt(parsedUrl.searchParams.get('index') || '0', 10);
        const events = this.state.escrowCoordinator.auditLog.getEvents();
        const tree = this.state.escrowCoordinator.auditLog.getMerkleTree();

        if (idx < 0 || idx >= events.length) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: `Event index ${idx} out of range (total: ${events.length}).` }));
          return;
        }

        const proof = tree.generateProof(idx);
        const targetEvent = events[idx];
        const isValid = MerkleTree.verifyProof(proof, tree.root);

        res.writeHead(200);
        res.end(
          JSON.stringify({
            index: idx,
            event: targetEvent,
            leafHash: proof.leafHash,
            siblings: proof.siblings,
            root: tree.root,
            isValid,
          })
        );
        return;
      }

      // -----------------------------------------------------------------------
      // 16. POST /api/vault/quick-seed
      // -----------------------------------------------------------------------
      if (pathname === '/api/vault/quick-seed' && method === 'POST') {
        if (!this.state.clientLocalState.dataKeyHex) {
          res.writeHead(409);
          res.end(JSON.stringify({ error: 'Recover the data key or log in before reinitializing this vault.' }));
          return;
        }
        this.state.seedDemoVault();
        res.writeHead(200);
        res.end(JSON.stringify({ success: true }));
        return;
      }

      res.writeHead(404);
      res.end(JSON.stringify({ error: `Route ${pathname} not found.` }));
    } catch (err: any) {
      res.writeHead(500);
      res.end(JSON.stringify({ error: err.message || 'Internal dashboard error' }));
    }
  };

  /**
   * Request handler serving API and Static Frontend Files.
   */
  private handleRequest = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
    const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;

    // API Routing
    if (pathname.startsWith('/api/')) {
      return this.handleApi(req, res);
    }

    // Static Asset Routing
    let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);

    // Guard against path traversal
    if (!filePath.startsWith(PUBLIC_DIR)) {
      res.writeHead(403);
      res.end('Forbidden');
      return;
    }

    fs.stat(filePath, (err, stats) => {
      if (err || !stats.isFile()) {
        filePath = path.join(PUBLIC_DIR, 'index.html');
      }

      const ext = path.extname(filePath).toLowerCase();
      const mimeTypes: Record<string, string> = {
        '.html': 'text/html; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
        '.json': 'application/json',
        '.png': 'image/png',
        '.svg': 'image/svg+xml',
      };
      const contentType = mimeTypes[ext] || 'application/octet-stream';

      fs.readFile(filePath, (readErr, content) => {
        if (readErr) {
          res.writeHead(500);
          res.end('Server Error');
          return;
        }
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(content);
      });
    });
  };

  /**
   * Starts server on specified TCP port or Named Pipe.
   */
  public start(portOrPipe: number | string = 3000): Promise<{ address: string; port?: number; url: string }> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer(this.handleRequest);

      this.server.on('error', (err: any) => {
        if (typeof portOrPipe === 'number' && err.code === 'EADDRINUSE') {
          // Retry on next port
          this.start(portOrPipe + 1).then(resolve).catch(reject);
        } else {
          reject(err);
        }
      });

      if (typeof portOrPipe === 'string') {
        this.server.listen(portOrPipe, () => {
          resolve({ address: portOrPipe, url: portOrPipe });
        });
      } else {
        this.server.listen(portOrPipe, '0.0.0.0', () => {
          const addr = this.server?.address();
          const actualPort = typeof addr === 'object' && addr ? addr.port : portOrPipe;
          const url = `http://localhost:${actualPort}`;
          resolve({ address: '127.0.0.1', port: actualPort, url });
        });
      }
    });
  }

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }
}

// Direct Execution Entrypoint
if (
  process.argv[1] &&
  path.resolve(process.argv[1]).toLowerCase() === fileURLToPath(import.meta.url).toLowerCase()
) {
  const port = parseInt(process.env.PORT || '3000', 10);
  const server = new DashboardServer();

  server.start(port).then(({ url, port: activePort }) => {
    console.log('\n========================================================================');
    console.log('🚀 TriVault Interactive Demonstration Dashboard is LIVE!');
    console.log(`🌐 Dashboard URL: ${url}`);
    console.log('========================================================================');
    console.log('Active Backend Services:');
    console.log('  • Panel 1: User Client & Android Simulator (Local Browser State)');
    console.log('  • Panel 2: Service Provider (SP) Zero-Knowledge Inspector');
    console.log('  • Panel 3: Escrow Cluster (N1, N2, N3) & Policy Engine (What/When/How)');
    console.log('  • Panel 4: Tamper-Evident Hash Chain & Merkle Tree Explorer');
    console.log('========================================================================\n');
  }).catch((err) => {
    console.error('Failed to start dashboard server:', err);
    process.exit(1);
  });
}
