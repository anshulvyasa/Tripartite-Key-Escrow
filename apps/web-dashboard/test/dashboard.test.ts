import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

import { DashboardServer } from '../src/server.ts';

describe('@trivault/web-dashboard - Live Demonstration Server & API Suite', () => {
  let server: DashboardServer;
  let baseUrl: string;

  const pipePath = `\\\\.\\pipe\\trivault-dashboard-${Date.now()}`;

  before(async () => {
    server = new DashboardServer();
    await server.start(pipePath);
  });

  after(async () => {
    await server.stop();
  });

  const request = (path: string, options: http.RequestOptions = {}, body?: any): Promise<{ status: number; data: any }> => {
    return new Promise((resolve, reject) => {
      const payload = body ? JSON.stringify(body) : undefined;
      const headers: Record<string, string> = {
        'Accept': 'application/json',
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload).toString() } : {}),
        ...(options.headers as any),
      };

      const req = http.request(
        {
          socketPath: pipePath,
          path,
          method: options.method || 'GET',
          headers,
        },
        (res) => {
          let chunks = '';
          res.on('data', (c) => (chunks += c));
          res.on('end', () => {
            try {
              const data = chunks ? JSON.parse(chunks) : {};
              resolve({ status: res.statusCode || 500, data });
            } catch {
              resolve({ status: res.statusCode || 500, data: chunks });
            }
          });
        }
      );

      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  };

  it('PROVE: GET /api/state returns full 4-panel system state snapshot', async () => {
    const { status, data } = await request('/api/state');
    assert.strictEqual(status, 200);

    // Panel 1: Client
    assert.ok(data.client);
    assert.strictEqual(data.client.vaultId, 'vault-demo-001');
    assert.ok(data.client.password);
    assert.ok(data.client.passwordKeyHex);
    assert.ok(data.client.dataKeyHex);
    assert.ok(data.client.userShare);
    assert.strictEqual(data.client.userShare.id, 1);
    assert.ok(data.client.schnorrKeys);
    assert.strictEqual(data.client.isVaultUnlocked, false);
    assert.ok(data.client.encryptedItems.length >= 4);
    assert.strictEqual(data.client.decryptedItems.length, 0);

    // Panel 2: SP
    assert.ok(data.serviceProvider);
    assert.strictEqual(data.serviceProvider.isOnline, true);
    assert.ok(data.serviceProvider.record);
    assert.strictEqual(data.serviceProvider.record.spShare.id, 2);

    // Panel 3: Escrow Cluster
    assert.ok(data.escrowCluster);
    assert.strictEqual(data.escrowCluster.onlineCount, 3);
    assert.strictEqual(data.escrowCluster.nodes.N1.online, true);
    assert.strictEqual(data.escrowCluster.nodes.N2.online, true);
    assert.strictEqual(data.escrowCluster.nodes.N3.online, true);

    // Panel 4: Audit & Merkle
    assert.ok(data.auditVerification);
    assert.strictEqual(data.auditVerification.chainValid, true);
    assert.strictEqual(data.auditVerification.checkpointValid, true);
  });

  it('PROVE: Algorithm 3 login succeeds with correct password and fails with wrong password (tag check)', async () => {
    // 1. Correct Password
    const goodLogin = await request('/api/vault/login', { method: 'POST' }, { password: 'MasterPassword#2026' });
    assert.strictEqual(goodLogin.status, 200);
    assert.strictEqual(goodLogin.data.success, true);
    assert.ok(goodLogin.data.decryptedItems.length >= 4);

    // 2. Wrong Password
    const badLogin = await request('/api/vault/login', { method: 'POST' }, { password: 'WrongPasswordGuess' });
    assert.strictEqual(badLogin.status, 401);
    assert.ok(badLogin.data.error.includes('Tag Failure') || badLogin.data.error.includes('Wrong password'));
  });

  it('PROVE: Manual Decrypt button decrypts vault with loaded K_data, and Lock button re-locks', async () => {
    // 1. Initial state before decrypt is locked
    const stateBefore = await request('/api/state');
    assert.strictEqual(stateBefore.data.client.isVaultUnlocked, false);
    assert.strictEqual(stateBefore.data.client.decryptedItems.length, 0);

    // 2. Click "Decrypt Vault" -> succeeds because K_data is loaded in memory
    const decryptRes = await request('/api/vault/decrypt', { method: 'POST' });
    assert.strictEqual(decryptRes.status, 200);
    assert.strictEqual(decryptRes.data.success, true);
    assert.strictEqual(decryptRes.data.isVaultUnlocked, true);
    assert.ok(decryptRes.data.decryptedItems.length >= 4);

    // Verify /api/state shows unlocked
    const stateUnlocked = await request('/api/state');
    assert.strictEqual(stateUnlocked.data.client.isVaultUnlocked, true);
    assert.ok(stateUnlocked.data.client.decryptedItems.length >= 4);

    // 3. Click "Lock Vault" -> re-locks vault and wipes plaintext items from memory
    const lockRes = await request('/api/vault/lock', { method: 'POST' });
    assert.strictEqual(lockRes.status, 200);
    assert.strictEqual(lockRes.data.success, true);
    assert.strictEqual(lockRes.data.isVaultUnlocked, false);

    // Verify /api/state shows locked again
    const stateLocked = await request('/api/state');
    assert.strictEqual(stateLocked.data.client.isVaultUnlocked, false);
    assert.strictEqual(stateLocked.data.client.decryptedItems.length, 0);

    // 4. Test Lock with purgeKey: true
    await request('/api/vault/lock', { method: 'POST' }, { purgeKey: true });
    const decryptWithoutKey = await request('/api/vault/decrypt', { method: 'POST' });
    assert.strictEqual(decryptWithoutKey.status, 400);
    assert.ok(decryptWithoutKey.data.error.includes('not loaded'));

    // Re-login with password to restore K_data for subsequent tests
    await request('/api/vault/login', { method: 'POST' }, { password: 'MasterPassword#2026' });
  });

  it('PROVE: SP Offline toggle blocks daily login but preserves zero-knowledge boundary', async () => {
    // 1. Toggle SP Offline
    const toggleOff = await request('/api/sp/toggle-offline', { method: 'POST' });
    assert.strictEqual(toggleOff.data.spOnline, false);

    // 2. Login fails because SP is unreachable
    const loginAttempt = await request('/api/vault/login', { method: 'POST' }, { password: 'MasterPassword#2026' });
    assert.strictEqual(loginAttempt.status, 503);
    assert.ok(loginAttempt.data.error.includes('OFFLINE'));

    // 3. Toggle SP back Online
    const toggleOn = await request('/api/sp/toggle-offline', { method: 'POST' });
    assert.strictEqual(toggleOn.data.spOnline, true);
  });

  it('PROVE: Escrow Node toggle tests 2-of-3 threshold fault tolerance', async () => {
    // 1. Take Node N1 Offline -> 2 nodes remain online (threshold satisfied)
    const toggleN1 = await request('/api/escrow/toggle-node', { method: 'POST' }, { nodeId: 'N1' });
    assert.strictEqual(toggleN1.data.nodesOnline.N1, false);

    // Algo 2 still initiates because N2 and N3 are online (2-of-3 satisfied)
    const algo2With2Nodes = await request('/api/vault/recover-algo2', { method: 'POST' });
    assert.strictEqual(algo2With2Nodes.status, 200);

    // Cancel the session
    await request('/api/vault/cancel-recovery', { method: 'POST' });

    // 2. Take Node N2 Offline -> only 1 node remains online (N3)
    const toggleN2 = await request('/api/escrow/toggle-node', { method: 'POST' }, { nodeId: 'N2' });
    assert.strictEqual(toggleN2.data.nodesOnline.N2, false);

    // Algo 2 now FAILS because 1 node < 2 threshold
    const algo2With1Node = await request('/api/vault/recover-algo2', { method: 'POST' });
    assert.strictEqual(algo2With1Node.status, 400);
    assert.ok(algo2With1Node.data.error.includes('2-of-3 threshold is required'));

    // 3. Restore N1 and N2 back online
    await request('/api/escrow/toggle-node', { method: 'POST' }, { nodeId: 'N1' });
    await request('/api/escrow/toggle-node', { method: 'POST' }, { nodeId: 'N2' });
  });

  it('PROVE: Forgot Password (U + S) recovers vault and resets master password', async () => {
    const newPassword = 'NewResetPassword#2027!';
    const res = await request('/api/vault/forgot-password', { method: 'POST' }, { newPassword });
    assert.strictEqual(res.status, 200);

    // Login with new password succeeds
    const newLogin = await request('/api/vault/login', { method: 'POST' }, { password: newPassword });
    assert.strictEqual(newLogin.status, 200);
  });

  it('PROVE: Algorithm 2 (U + E) recovery with automatic key rotation and completion', async () => {
    // 1. Initiate Algo 2 with 20ms delay for fast test verification
    const initRes = await request('/api/vault/recover-algo2', { method: 'POST' }, { delayMs: 20 });
    assert.strictEqual(initRes.status, 200);
    assert.strictEqual(initRes.data.session.status, 'PENDING_DELAY');

    // Wait for 20ms timelock to expire
    await new Promise((r) => setTimeout(r, 40));

    // 2. Complete Recovery
    const completeRes = await request('/api/vault/complete-recovery', { method: 'POST' });
    assert.strictEqual(completeRes.status, 200);
    assert.ok(completeRes.data.items.length >= 4);
  });

  it('PROVE: Password from Algorithm 1 remains valid for Algorithm 3 login after Algorithm 2 recovery', async () => {
    const customPassword = 'CustomMasterSecret#9988';
    const customItems = [
      { id: 'item-custom-1', title: 'Personal Monero Seed', category: 'Crypto', secret: 'monero-secret-seed-xyz' },
    ];

    // 1. Run Algorithm 1 Setup with custom password and custom secrets
    const setupRes = await request(
      '/api/vault/setup',
      { method: 'POST' },
      {
        vaultId: 'vault-custom-test',
        password: customPassword,
        items: customItems,
        recoveryMode: 'RECOVERABLE',
      }
    );
    assert.strictEqual(setupRes.status, 200);
    assert.strictEqual(setupRes.data.itemCount, 1);

    // 2. Lock vault to verify recovery flow
    await request('/api/vault/lock', { method: 'POST' }, { purgeKey: true });

    // 3. Initiate and complete Algorithm 2 (U + E) Recovery
    const initRes = await request('/api/vault/recover-algo2', { method: 'POST' }, { delayMs: 15 });
    assert.strictEqual(initRes.status, 200);
    await new Promise((r) => setTimeout(r, 30));
    const compRes = await request('/api/vault/complete-recovery', { method: 'POST' });
    assert.strictEqual(compRes.status, 200);

    // 4. Lock vault again so we can test normal login
    await request('/api/vault/lock', { method: 'POST' }, { purgeKey: true });

    // 5. Algorithm 3 Login with the custom password set in Algorithm 1 -> MUST SUCCEED
    const loginRes = await request('/api/vault/login', { method: 'POST' }, { password: customPassword });
    assert.strictEqual(loginRes.status, 200);

    // 6. Manual decrypt reveals the custom secret added during Algorithm 1
    const decryptRes = await request('/api/vault/decrypt', { method: 'POST' });
    assert.strictEqual(decryptRes.status, 200);
    assert.strictEqual(decryptRes.data.decryptedItems[0].title, 'Personal Monero Seed');
    assert.strictEqual(decryptRes.data.decryptedItems[0].secret, 'monero-secret-seed-xyz');

    // 7. Verify an incorrect password fails tag check
    const badLogin = await request('/api/vault/login', { method: 'POST' }, { password: 'WrongPasswordAfterAlgo2' });
    assert.strictEqual(badLogin.status, 401);
    assert.ok(badLogin.data.error.includes('Authentication Tag Failure'));
  });

  it('PROVE: Algorithm 1 dynamically adds new key-value secrets, unlocks vault, and retains state', async () => {
    const freshSecrets = [
      { id: 'item-1', title: 'Ethereum Staking Key', category: 'Personal', secret: '0xethsecretvalue9999' },
      { id: 'item-2', title: 'GitHub Deployment Token', category: 'Personal', secret: 'ghp_deploymentToken123456789' },
      { id: 'item-3', title: 'Vault Passphrase Backup', category: 'Personal', secret: 'my-ultra-secret-passphrase' },
    ];

    const setupRes = await request(
      '/api/vault/setup',
      { method: 'POST' },
      {
        vaultId: 'vault-dynamic-keys',
        password: 'DynamicSetupMaster#2026',
        items: freshSecrets,
        recoveryMode: 'RECOVERABLE',
      }
    );
    assert.strictEqual(setupRes.status, 200);
    assert.strictEqual(setupRes.data.itemCount, 3);

    // Verify /api/state immediately reflects the newly added secrets in unlocked state
    const stateRes = await request('/api/state');
    assert.strictEqual(stateRes.data.client.isVaultUnlocked, true);
    assert.strictEqual(stateRes.data.client.decryptedItems.length, 3);
    assert.strictEqual(stateRes.data.client.decryptedItems[0].title, 'Ethereum Staking Key');
    assert.strictEqual(stateRes.data.client.decryptedItems[0].secret, '0xethsecretvalue9999');
    assert.strictEqual(stateRes.data.client.decryptedItems[1].title, 'GitHub Deployment Token');
    assert.strictEqual(stateRes.data.client.decryptedItems[1].secret, 'ghp_deploymentToken123456789');
    assert.strictEqual(stateRes.data.client.decryptedItems[2].title, 'Vault Passphrase Backup');
    assert.strictEqual(stateRes.data.client.decryptedItems[2].secret, 'my-ultra-secret-passphrase');

    // Test locking and unlocking
    await request('/api/vault/lock', { method: 'POST' });
    const stateLocked = await request('/api/state');
    assert.strictEqual(stateLocked.data.client.isVaultUnlocked, false);

    const decryptRes = await request('/api/vault/decrypt', { method: 'POST' });
    assert.strictEqual(decryptRes.status, 200);
    assert.strictEqual(decryptRes.data.decryptedItems.length, 3);
  });

  it('preserves an explicitly empty vault and can add a secret after clearing it', async () => {
    const cleared = await request('/api/vault/setup', { method: 'POST' }, {
      vaultId: 'vault-empty',
      password: '  Exact Password  ',
      items: [],
    });
    assert.strictEqual(cleared.status, 200);
    assert.strictEqual(cleared.data.itemCount, 0);
    const emptyState = await request('/api/state');
    assert.strictEqual(emptyState.data.client.isVaultUnlocked, true);
    assert.deepEqual(emptyState.data.client.activeItems, []);
    assert.deepEqual(emptyState.data.client.encryptedItems, []);
    await request('/api/vault/lock', { method: 'POST' }, { purgeKey: true });
    const login = await request('/api/vault/login', { method: 'POST' }, { password: '  Exact Password  ' });
    assert.strictEqual(login.status, 200);
    const decrypted = await request('/api/vault/decrypt', { method: 'POST' });
    assert.deepEqual(decrypted.data.decryptedItems, []);

    const items = [{ id: '1', title: 'New secret', category: 'Personal', secret: '  exact secret  ' }];
    const added = await request('/api/vault/setup', { method: 'POST' }, {
      vaultId: 'vault-empty', password: '  Exact Password  ', items,
    });
    assert.strictEqual(added.status, 200);
    await request('/api/vault/lock', { method: 'POST' });
    const restored = await request('/api/vault/decrypt', { method: 'POST' });
    assert.deepEqual(restored.data.decryptedItems, items);
  });

  it('rejects stale setup forms so a later save cannot delete newly added secrets', async () => {
    const original = (await request('/api/state')).data;
    const originalItems = original.client.activeItems;
    const expectedVaultIv = original.serviceProvider.record.fullCiphertext.iv;
    const items = [...originalItems, { id: 'new-secret', title: 'Added in another tab', category: 'Personal', secret: 'keep-me' }];
    const saved = await request('/api/vault/setup', { method: 'POST' }, {
      vaultId: original.client.vaultId, password: original.client.password, items, expectedVaultIv,
    });
    assert.strictEqual(saved.status, 200);
    const stale = await request('/api/vault/setup', { method: 'POST' }, {
      vaultId: original.client.vaultId, password: original.client.password, items: originalItems, expectedVaultIv,
    });
    assert.strictEqual(stale.status, 409);
    const overwrite = await request('/api/vault/setup', { method: 'POST' }, {
      vaultId: original.client.vaultId, password: original.client.password, items: [], expectedVaultIv: null,
    });
    assert.strictEqual(overwrite.status, 409);
    const decrypted = await request('/api/vault/decrypt', { method: 'POST' });
    assert.deepEqual(decrypted.data.decryptedItems, items);
  });

  it('rejects invalid setup input before changing the active vault', async () => {
    const before = (await request('/api/state')).data.client;
    for (const invalid of [{ password: '' }, { items: {} }, { items: [null] }, { items: [{ secret: 42 }] }]) {
      const result = await request('/api/vault/setup', { method: 'POST' }, {
        vaultId: 'invalid-vault', password: 'AnotherPassword', ...invalid,
      });
      assert.strictEqual(result.status, 400);
      const after = (await request('/api/state')).data.client;
      assert.deepEqual(after, before);
    }
  });

  it('PROVE: Strict Mode enforcement strictly rejects Algorithm 4 (S + E)', async () => {
    // 1. Set Vault Mode to STRICT
    await request('/api/client/vault-mode', { method: 'POST' }, { recoveryMode: 'STRICT' });

    // 2. Attempt Algorithm 4 Total Loss -> MUST BE REJECTED
    const algo4Strict = await request('/api/vault/recover-algo4', { method: 'POST' });
    assert.strictEqual(algo4Strict.status, 403);
    assert.ok(algo4Strict.data.error.includes('Strict Mode Violation'));

    // 3. Restore to RECOVERABLE
    await request('/api/client/vault-mode', { method: 'POST' }, { recoveryMode: 'RECOVERABLE' });
  });

  it('PROVE: Tamper simulator mutates Event 3 and detects broken hash chain and invalid Merkle root', async () => {
    // 1. Trigger Tamper with Event 3
    const tamperRes = await request('/api/audit/tamper-event3', { method: 'POST' });
    assert.strictEqual(tamperRes.status, 200);

    // 2. Check state: integrity check must fail!
    const stateAfterTamper = await request('/api/state');
    assert.strictEqual(stateAfterTamper.data.auditVerification.chainValid, false);
    assert.strictEqual(stateAfterTamper.data.auditVerification.tamperedEvent3, true);

    // 3. Restore Tamper
    const restoreRes = await request('/api/audit/restore', { method: 'POST' });
    assert.strictEqual(restoreRes.status, 200);

    // 4. Verify integrity is restored
    const stateAfterRestore = await request('/api/state');
    assert.strictEqual(stateAfterRestore.data.auditVerification.chainValid, true);
    assert.strictEqual(stateAfterRestore.data.auditVerification.tamperedEvent3, false);
  });

  it('PROVE: Merkle Inclusion Proof endpoint returns valid RFC 6962 proof path', async () => {
    const proofRes = await request('/api/audit/merkle-proof?index=0');
    assert.strictEqual(proofRes.status, 200);
    assert.strictEqual(proofRes.data.index, 0);
    assert.ok(proofRes.data.leafHash);
    assert.ok(proofRes.data.root);
    assert.strictEqual(proofRes.data.isValid, true);
  });

  it('simulates key loss and recovers the original vault through Algorithm 2', async () => {
    const items = [{ id: 'key-loss-secret', title: 'Recovery test', category: 'Personal', secret: 'recover-this-exact-value' }];
    await request('/api/vault/setup', { method: 'POST' }, {
      vaultId: 'vault-key-loss', password: 'KeyLossPassword', items,
    });
    const before = (await request('/api/state')).data;
    const lost = await request('/api/vault/lock', { method: 'POST' }, { purgeKey: true });
    assert.strictEqual(lost.status, 200);
    assert.strictEqual(lost.data.keyRetained, false);
    const missing = (await request('/api/state')).data;
    assert.strictEqual(missing.client.isVaultUnlocked, false);
    for (const key of ['dataKeyHex', 'passwordKeyHex', 'recoveryKeyHex', 'password']) {
      assert.strictEqual(missing.client[key], '');
    }
    assert.deepEqual(missing.client.decryptedItems, []);
    assert.deepEqual(missing.client.activeItems, []);
    assert.deepEqual(server.state.currentVaultItems, []);
    assert.deepEqual(missing.client.userShare, before.client.userShare);
    assert.deepEqual(missing.client.schnorrKeys, before.client.schnorrKeys);
    assert.deepEqual(missing.client.cachedCiphertext, before.client.cachedCiphertext);
    assert.deepEqual(missing.serviceProvider.record, before.serviceProvider.record);
    assert.strictEqual((await request('/api/vault/decrypt', { method: 'POST' })).status, 400);

    // Repeating the action and ordinary locking cannot restore the missing key.
    await request('/api/vault/lock', { method: 'POST' }, { purgeKey: true });
    await request('/api/vault/lock', { method: 'POST' });
    assert.strictEqual((await request('/api/state')).data.client.dataKeyHex, '');
    assert.strictEqual((await request('/api/vault/quick-seed', { method: 'POST' })).status, 409);
    const replace = await request('/api/vault/setup', { method: 'POST' }, {
      vaultId: 'vault-key-loss', password: 'Replacement', items: [],
    });
    assert.strictEqual(replace.status, 409);
    const wrongPassword = await request('/api/vault/login', { method: 'POST' }, { password: 'WrongPassword' });
    assert.strictEqual(wrongPassword.status, 401);
    assert.strictEqual((await request('/api/state')).data.client.dataKeyHex, '');

    const recovery = await request('/api/vault/recover-algo2', { method: 'POST' }, { delayMs: 60 });
    assert.strictEqual(recovery.status, 200);
    assert.strictEqual((await request('/api/state')).data.client.dataKeyHex, '');
    await new Promise((resolve) => setTimeout(resolve, 80));
    const completed = await request('/api/vault/complete-recovery', { method: 'POST' });
    assert.strictEqual(completed.status, 200);
    assert.strictEqual(completed.data.dataKeyHex, before.client.dataKeyHex);
    assert.deepEqual((await request('/api/vault/decrypt', { method: 'POST' })).data.decryptedItems, items);
    const recovered = (await request('/api/state')).data;
    assert.deepEqual(recovered.client.activeItems, items);
    assert.deepEqual(server.state.currentVaultItems, items);
  });

  it('restores access through login, password reset and Algorithm 4 after key loss', async () => {
    const before = (await request('/api/state')).data.client;
    await request('/api/vault/lock', { method: 'POST' }, { purgeKey: true });
    const login = await request('/api/vault/login', { method: 'POST' }, { password: 'KeyLossPassword', autoDecrypt: true });
    assert.strictEqual(login.status, 200);
    assert.deepEqual(login.data.decryptedItems, before.activeItems);
    assert.deepEqual((await request('/api/state')).data.client.activeItems, before.activeItems);

    await request('/api/vault/lock', { method: 'POST' }, { purgeKey: true });
    const reset = await request('/api/vault/forgot-password', { method: 'POST' }, { newPassword: 'ResetAfterKeyLoss' });
    assert.strictEqual(reset.status, 200);
    assert.strictEqual(reset.data.dataKeyHex, before.dataKeyHex);
    assert.deepEqual((await request('/api/state')).data.client.activeItems, before.activeItems);

    await request('/api/vault/lock', { method: 'POST' }, { purgeKey: true });
    const recovery = await request('/api/vault/recover-algo4', { method: 'POST' }, { delayMs: 20 });
    assert.strictEqual(recovery.status, 200);
    await new Promise((resolve) => setTimeout(resolve, 40));
    const completed = await request('/api/vault/complete-recovery', { method: 'POST' });
    assert.strictEqual(completed.status, 200);
    assert.strictEqual(completed.data.dataKeyHex, before.dataKeyHex);
    assert.deepEqual((await request('/api/vault/decrypt', { method: 'POST' })).data.decryptedItems, before.activeItems);
    assert.deepEqual((await request('/api/state')).data.client.activeItems, before.activeItems);
  });

  it('PROVE: Static frontend files (index.html, dashboard.css, dashboard.js) are served properly', async () => {
    const htmlRes = await request('/');
    assert.strictEqual(htmlRes.status, 200);
    assert.ok(htmlRes.data.includes('TriVault') && htmlRes.data.includes('Demonstration Dashboard'));

    const cssRes = await request('/dashboard.css');
    assert.strictEqual(cssRes.status, 200);
    assert.ok(cssRes.data.includes('--bg-main'));

    const jsRes = await request('/dashboard.js');
    assert.strictEqual(jsRes.status, 200);
    assert.ok(jsRes.data.includes('renderAll'));
    assert.ok(jsRes.data.includes('triggerManualDecrypt'));
    assert.ok(jsRes.data.includes('triggerManualLock'));
    assert.ok(jsRes.data.includes('toggleInspectorPassword'));
  });
});
