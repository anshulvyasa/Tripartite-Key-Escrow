import type {
  AuditEvent,
  ChainVerificationResult,
  MerkleProof,
  RootCheckpoint,
  SignedRootCheckpoint,
} from './types.ts';
import { HashChain } from './hash-chain.ts';
import { MerkleTree } from './merkle-tree.ts';
import { createSignedCheckpoint, verifySignedCheckpoint } from './checkpoint.ts';

export class AuditLog {
  private readonly chain: HashChain;
  private cachedTree: MerkleTree | null = null;
  private currentEpoch: number = 0;

  constructor(initialEvents: AuditEvent[] = []) {
    this.chain = new HashChain(initialEvents);
  }

  /**
   * Appends an event to the append-only hash chain.
   */
  append<T = Record<string, unknown>>(
    action: string,
    actor: string,
    payload: T,
    timestamp: number = Date.now()
  ): AuditEvent<T> {
    const event = this.chain.append(action, actor, payload, timestamp);
    // Invalidate cached Merkle tree since leaves have expanded
    this.cachedTree = null;
    return event;
  }

  /**
   * Returns all recorded audit events.
   */
  getEvents(): ReadonlyArray<AuditEvent> {
    return this.chain.getEvents();
  }

  /**
   * Retrieves an event by sequence index.
   */
  getEvent(index: number): AuditEvent | undefined {
    return this.chain.getEvent(index);
  }

  /**
   * Retrieves the current head event.
   */
  getHead(): AuditEvent | undefined {
    return this.chain.getHead();
  }

  /**
   * Returns the current head hash.
   */
  getHeadHash(): string {
    return this.chain.getHeadHash();
  }

  /**
   * Total number of events.
   */
  get length(): number {
    return this.chain.length;
  }

  /**
   * Validates the integrity of the hash chain from genesis to head.
   */
  verifyChainIntegrity(): ChainVerificationResult {
    return this.chain.verifyIntegrity();
  }

  /**
   * Builds or returns the cached Merkle Tree over all event hashes.
   */
  getMerkleTree(): MerkleTree {
    if (!this.cachedTree) {
      const eventHashes = this.chain.getEvents().map((e) => e.hash);
      this.cachedTree = new MerkleTree(eventHashes);
    }
    return this.cachedTree;
  }

  /**
   * Computes the current Merkle root over all event hashes.
   */
  getMerkleRoot(): string {
    return this.getMerkleTree().root;
  }

  /**
   * Generates a Merkle inclusion proof for the event at the specified index.
   */
  generateInclusionProof(eventIndex: number): MerkleProof {
    const tree = this.getMerkleTree();
    return tree.generateProof(eventIndex);
  }

  /**
   * Verifies a Merkle inclusion proof against an expected root (or current log root).
   */
  verifyInclusionProof(proof: MerkleProof, expectedRoot?: string): boolean {
    const targetRoot = expectedRoot ?? this.getMerkleRoot();
    return MerkleTree.verifyProof(proof, targetRoot);
  }

  /**
   * Creates a signed root checkpoint anchoring the current chain head and Merkle root.
   */
  createSignedCheckpoint(
    signerPrivateKey: Uint8Array | string,
    signerPublicKey: Uint8Array | string,
    customEpoch?: number
  ): SignedRootCheckpoint {
    const epoch = customEpoch ?? ++this.currentEpoch;
    const lastEventIndex = this.chain.length - 1;
    const chainHeadHash = this.chain.getHeadHash();
    const merkleRoot = this.getMerkleRoot();

    const checkpoint: RootCheckpoint = {
      epoch,
      lastEventIndex,
      chainHeadHash,
      merkleRoot,
      timestamp: Date.now(),
    };

    return createSignedCheckpoint(checkpoint, signerPrivateKey, signerPublicKey);
  }

  /**
   * Verifies the signature of a signed root checkpoint.
   */
  verifySignedCheckpoint(signedCheckpoint: SignedRootCheckpoint): boolean {
    return verifySignedCheckpoint(signedCheckpoint);
  }

  /**
   * INTERNAL TESTING UTILITY ONLY:
   * Mutates an internal event in memory to simulate malicious database tampering or unauthorized alteration.
   */
  _tamperEventForTesting(
    index: number,
    modifier: (event: AuditEvent) => void
  ): void {
    const event = (this.chain as any).events[index];
    if (!event) throw new Error(`Event at index ${index} not found for tampering test`);
    modifier(event);
    // Invalidate cached Merkle tree so fresh tree reflects modified leaves
    this.cachedTree = null;
  }
}
