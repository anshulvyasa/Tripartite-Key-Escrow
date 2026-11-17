import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateSchnorrKeyPair } from '@trivault/crypto-core';

import {
  AuditLog,
  HashChain,
  MerkleTree,
  computeEventHash,
  hashLeaf,
  GENESIS_PREV_HASH,
  type AuditEvent,
} from '../src/index.ts';

describe('packages/audit-log Test Suite', () => {
  let auditLog: AuditLog;
  let authorityKeys: ReturnType<typeof generateSchnorrKeyPair>;

  beforeEach(() => {
    auditLog = new AuditLog();
    authorityKeys = generateSchnorrKeyPair();
  });

  // =========================================================================
  // 1. Hash Chain Operations & Integrity Verification
  // =========================================================================
  describe('Append-Only Hash Chain', () => {
    it('should correctly initialize and append events with strict hash linkage', () => {
      const e0 = auditLog.append('VAULT_INITIALIZED', 'user-alice', { vaultId: 'vault-001' });
      const e1 = auditLog.append('SHARE_DISTRIBUTED', 'service-provider', { shareType: 'S', recipient: 'sp-vault' });
      const e2 = auditLog.append('ESCROW_NODES_REGISTERED', 'coordinator', { nodes: ['N1', 'N2', 'N3'] });

      assert.strictEqual(auditLog.length, 3);

      // Event 0 must link to Genesis
      assert.strictEqual(e0.index, 0);
      assert.strictEqual(e0.prevHash, GENESIS_PREV_HASH);
      assert.strictEqual(e0.hash, computeEventHash(e0));

      // Event 1 must link to Event 0
      assert.strictEqual(e1.index, 1);
      assert.strictEqual(e1.prevHash, e0.hash);
      assert.strictEqual(e1.hash, computeEventHash(e1));

      // Event 2 must link to Event 1
      assert.strictEqual(e2.index, 2);
      assert.strictEqual(e2.prevHash, e1.hash);
      assert.strictEqual(e2.hash, computeEventHash(e2));

      // Complete chain verification must succeed
      const verification = auditLog.verifyChainIntegrity();
      assert.strictEqual(verification.valid, true);
      assert.strictEqual(verification.totalEvents, 3);
    });

    it('should verify chain integrity across an extensive multi-event lifecycle', () => {
      const actions = [
        { action: 'VAULT_CREATED', actor: 'alice', payload: { id: 1 } },
        { action: 'SHARE_U_SAVED', actor: 'alice', payload: { client: 'cli' } },
        { action: 'SHARE_S_STORED', actor: 'sp', payload: { encrypted: true } },
        { action: 'SHARE_E_SPLIT', actor: 'escrow', payload: { nodes: 3 } },
        { action: 'RECOVERY_REQUEST', actor: 'alice', payload: { ticketId: 'REC-999' } },
        { action: 'CHALLENGE_ISSUED', actor: 'coordinator', payload: { nonce: 'abc' } },
        { action: 'CHALLENGE_VERIFIED', actor: 'coordinator', payload: { valid: true } },
        { action: 'DELAY_TIMER_STARTED', actor: 'timer', payload: { delayMinutes: 60 } },
        { action: 'NODE_SHARES_RELEASED', actor: 'n1,n2', payload: { count: 2 } },
        { action: 'VAULT_RESTORED', actor: 'alice', payload: { success: true } },
      ];

      for (const item of actions) {
        auditLog.append(item.action, item.actor, item.payload);
      }

      assert.strictEqual(auditLog.length, 10);
      const res = auditLog.verifyChainIntegrity();
      assert.strictEqual(res.valid, true);
      assert.strictEqual(res.totalEvents, 10);
      assert.strictEqual(res.brokenIndex, undefined);
    });
  });

  // =========================================================================
  // 2. Merkle Tree Engine & Inclusion Proofs
  // =========================================================================
  describe('Merkle Tree Engine & Inclusion Proofs', () => {
    it('should build a deterministic Merkle Tree and generate valid inclusion proofs', () => {
      // Populate 6 events
      for (let i = 0; i < 6; i++) {
        auditLog.append(`ACTION_${i}`, `actor_${i}`, { eventIndex: i });
      }

      const merkleRoot = auditLog.getMerkleRoot();
      assert.ok(merkleRoot);
      assert.strictEqual(merkleRoot.length, 64); // 32-byte SHA-256 hex string

      // Verify Merkle inclusion proofs for every single event (0 through 5)
      for (let i = 0; i < 6; i++) {
        const proof = auditLog.generateInclusionProof(i);
        assert.strictEqual(proof.leafIndex, i);
        assert.strictEqual(proof.merkleRoot, merkleRoot);

        // Verification against valid root must succeed
        const isValid = auditLog.verifyInclusionProof(proof, merkleRoot);
        assert.strictEqual(isValid, true, `Inclusion proof for leaf ${i} must verify`);
      }
    });

    it('should reject Merkle inclusion proofs against mismatched or fake root', () => {
      for (let i = 0; i < 4; i++) {
        auditLog.append(`EVENT_${i}`, 'actor', { count: i });
      }

      const proof = auditLog.generateInclusionProof(2);
      const fakeRoot = 'f'.repeat(64);

      const isValid = auditLog.verifyInclusionProof(proof, fakeRoot);
      assert.strictEqual(isValid, false, 'Proof must fail against a forged Merkle root');
    });

    it('should reject Merkle inclusion proofs with corrupted siblings', () => {
      for (let i = 0; i < 4; i++) {
        auditLog.append(`EVENT_${i}`, 'actor', { val: i });
      }

      const proof = auditLog.generateInclusionProof(1);
      // Corrupt the first sibling hash
      proof.siblings[0].hash = '00'.repeat(32);

      const isValid = auditLog.verifyInclusionProof(proof);
      assert.strictEqual(isValid, false, 'Proof with corrupted sibling hash must fail');
    });
  });

  // =========================================================================
  // 3. Signed Root Checkpoints
  // =========================================================================
  describe('Signed Root Checkpoints', () => {
    it('should generate and verify cryptographically signed root checkpoints using Schnorr', () => {
      auditLog.append('AUTH_EVENT_1', 'system', { status: 'boot' });
      auditLog.append('AUTH_EVENT_2', 'admin', { status: 'ready' });

      // Create signed checkpoint anchoring head hash and Merkle root
      const signedCheckpoint = auditLog.createSignedCheckpoint(
        authorityKeys.privateKey,
        authorityKeys.publicKeyHex,
        1 // epoch 1
      );

      assert.strictEqual(signedCheckpoint.checkpoint.epoch, 1);
      assert.strictEqual(signedCheckpoint.checkpoint.lastEventIndex, 1);
      assert.strictEqual(signedCheckpoint.checkpoint.chainHeadHash, auditLog.getHeadHash());
      assert.strictEqual(signedCheckpoint.checkpoint.merkleRoot, auditLog.getMerkleRoot());
      assert.ok(signedCheckpoint.signature);
      assert.strictEqual(signedCheckpoint.signerPublicKey, authorityKeys.publicKeyHex);

      // Verify checkpoint signature
      const isValid = auditLog.verifySignedCheckpoint(signedCheckpoint);
      assert.strictEqual(isValid, true, 'Signed checkpoint signature must verify');
    });

    it('should reject checkpoint if signature or checkpoint data is tampered', () => {
      auditLog.append('TEST_EVENT', 'user', { data: 123 });

      const signedCheckpoint = auditLog.createSignedCheckpoint(
        authorityKeys.privateKey,
        authorityKeys.publicKeyHex
      );

      // 1. Alter checkpoint data (e.g. forged root)
      const tamperedCheckpoint = {
        ...signedCheckpoint,
        checkpoint: {
          ...signedCheckpoint.checkpoint,
          merkleRoot: '11'.repeat(32), // Malicious altered root
        },
      };
      assert.strictEqual(
        auditLog.verifySignedCheckpoint(tamperedCheckpoint),
        false,
        'Tampered checkpoint data must fail verification'
      );

      // 2. Corrupted signature bytes
      const corruptedSigCheckpoint = {
        ...signedCheckpoint,
        signature: 'ff'.repeat(64),
      };
      assert.strictEqual(
        auditLog.verifySignedCheckpoint(corruptedSigCheckpoint),
        false,
        'Invalid signature must fail verification'
      );

      // 3. Signed with unauthorized key
      const impostorKeys = generateSchnorrKeyPair();
      const impostorSigned = auditLog.createSignedCheckpoint(
        impostorKeys.privateKey,
        impostorKeys.publicKeyHex
      );
      // Attempting to claim it was signed by legitimate authority
      const spoofedCheckpoint = {
        ...impostorSigned,
        signerPublicKey: authorityKeys.publicKeyHex,
      };
      assert.strictEqual(
        auditLog.verifySignedCheckpoint(spoofedCheckpoint),
        false,
        'Key spoofing must fail verification'
      );
    });
  });

  // =========================================================================
  // 4. Tamper Detection (e.g., Event 3 modified)
  // =========================================================================
  describe('Tamper Detection Engine', () => {
    it('PROVE: detect tampering if an existing event (Event 3) payload is modified', () => {
      // 1. Populate log with 6 events
      auditLog.append('EVENT_0', 'actor-0', { data: 'Genesis state' });
      auditLog.append('EVENT_1', 'actor-1', { data: 'Node keys initialized' });
      auditLog.append('EVENT_2', 'actor-2', { data: 'User registered' });
      auditLog.append('EVENT_3', 'escrow-node-1', {
        action: 'APPROVE_RECOVERY',
        authorizedTarget: 'user-alice',
        amount: 500,
      });
      auditLog.append('EVENT_4', 'escrow-node-2', { action: 'APPROVE_RECOVERY', target: 'user-alice' });
      auditLog.append('EVENT_5', 'service-provider', { action: 'KEY_RELEASED', target: 'user-alice' });

      // Initial integrity check succeeds
      assert.strictEqual(auditLog.verifyChainIntegrity().valid, true);

      // Anchor checkpoint with authentic Merkle root and head
      const authenticCheckpoint = auditLog.createSignedCheckpoint(
        authorityKeys.privateKey,
        authorityKeys.publicKeyHex,
        1
      );
      const originalEvent3Proof = auditLog.generateInclusionProof(3);
      assert.strictEqual(
        auditLog.verifyInclusionProof(originalEvent3Proof, authenticCheckpoint.checkpoint.merkleRoot),
        true
      );

      // =====================================================================
      // Scenario A: Malicious actor mutates Event 3 payload without updating hash
      // (e.g. changing authorizedTarget to 'attacker-mallory')
      // =====================================================================
      auditLog._tamperEventForTesting(3, (e: AuditEvent) => {
        (e.payload as any).authorizedTarget = 'attacker-mallory';
        (e.payload as any).amount = 999999;
      });

      // Hash chain verification MUST detect tampering directly at index 3
      const chainCheckTamperedContent = auditLog.verifyChainIntegrity();
      assert.strictEqual(chainCheckTamperedContent.valid, false, 'Chain must be detected as invalid');
      assert.strictEqual(chainCheckTamperedContent.brokenIndex, 3, 'Tamper must be detected at Event 3');
      assert.match(
        chainCheckTamperedContent.reason!,
        /Content hash mismatch at index 3/,
        'Reason must explicitly identify content hash mismatch'
      );

      // =====================================================================
      // Scenario B: Attacker attempts to forge Event 3's hash to match tampered payload
      // =====================================================================
      auditLog._tamperEventForTesting(3, (e: AuditEvent) => {
        // Recompute hash for Event 3 with tampered payload
        e.hash = computeEventHash(e);
      });

      // Now Event 3's own content matches its hash, BUT Event 4's prevHash still points to the old hash!
      const chainCheckBrokenLink = auditLog.verifyChainIntegrity();
      assert.strictEqual(chainCheckBrokenLink.valid, false, 'Chain must be detected as invalid');
      assert.strictEqual(chainCheckBrokenLink.brokenIndex, 4, 'Tamper must be detected at Event 4 prevHash link');
      assert.match(
        chainCheckBrokenLink.reason!,
        /Previous hash mismatch at index 4/,
        'Linkage break must be detected at subsequent event'
      );

      // =====================================================================
      // Scenario C: Merkle root and inclusion proof tamper detection
      // =====================================================================
      // The tree recomputed over tampered event produces a completely different root
      const newMerkleRoot = auditLog.getMerkleRoot();
      assert.notStrictEqual(
        newMerkleRoot,
        authenticCheckpoint.checkpoint.merkleRoot,
        'Tampered event produces a conflicting Merkle root'
      );

      // The authentic signed checkpoint rejects the new Merkle root
      assert.strictEqual(
        newMerkleRoot === authenticCheckpoint.checkpoint.merkleRoot,
        false,
        'Tampered log state does not match signed root checkpoint'
      );

      // Inclusion proof created for tampered event 3 against authentic root fails
      const tamperedEvent3Proof = auditLog.generateInclusionProof(3);
      const isTamperedProofValid = auditLog.verifyInclusionProof(
        tamperedEvent3Proof,
        authenticCheckpoint.checkpoint.merkleRoot
      );
      assert.strictEqual(
        isTamperedProofValid,
        false,
        'Inclusion proof of tampered Event 3 must fail against signed checkpoint root'
      );
    });

    it('should detect tampering if an event index is modified or out-of-order', () => {
      auditLog.append('E0', 'actor', {});
      auditLog.append('E1', 'actor', {});
      auditLog.append('E2', 'actor', {});

      auditLog._tamperEventForTesting(1, (e: AuditEvent) => {
        (e as any).index = 99; // Corrupt sequence index
      });

      const check = auditLog.verifyChainIntegrity();
      assert.strictEqual(check.valid, false);
      assert.strictEqual(check.brokenIndex, 1);
      assert.match(check.reason!, /Sequence index mismatch at position 1/);
    });
  });
});
