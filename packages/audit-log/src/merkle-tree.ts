import crypto from 'node:crypto';
import type { MerkleProof, MerkleProofSibling } from './types.ts';

const EMPTY_ROOT_HASH = '0'.repeat(64);

/**
 * RFC 6962 second-preimage resistant leaf hash: SHA-256(0x00 || leafData)
 */
export function hashLeaf(leafDataHex: string): string {
  const prefix = Buffer.from([0x00]);
  const leafBytes = Buffer.from(leafDataHex, 'hex');
  return crypto.createHash('sha256').update(Buffer.concat([prefix, leafBytes])).digest('hex');
}

/**
 * RFC 6962 interior node hash: SHA-256(0x01 || leftChild || rightChild)
 */
export function hashInternalNode(leftHex: string, rightHex: string): string {
  const prefix = Buffer.from([0x01]);
  const leftBytes = Buffer.from(leftHex, 'hex');
  const rightBytes = Buffer.from(rightHex, 'hex');
  return crypto
    .createHash('sha256')
    .update(Buffer.concat([prefix, leftBytes, rightBytes]))
    .digest('hex');
}

/**
 * Merkle Tree structure and proof engine for audit events.
 */
export class MerkleTree {
  private readonly rawLeaves: string[];
  private readonly layers: string[][];
  public readonly root: string;

  constructor(leafHashes: string[]) {
    this.rawLeaves = [...leafHashes];

    if (this.rawLeaves.length === 0) {
      this.layers = [];
      this.root = EMPTY_ROOT_HASH;
      return;
    }

    // Layer 0: Hashed leaves
    let currentLayer = this.rawLeaves.map(hashLeaf);
    this.layers = [currentLayer];

    // Build tree layers upwards until root is reached
    while (currentLayer.length > 1) {
      const nextLayer: string[] = [];
      for (let i = 0; i < currentLayer.length; i += 2) {
        const left = currentLayer[i];
        // If odd number of nodes in layer, duplicate last node
        const right = i + 1 < currentLayer.length ? currentLayer[i + 1] : left;
        nextLayer.push(hashInternalNode(left, right));
      }
      this.layers.push(nextLayer);
      currentLayer = nextLayer;
    }

    this.root = currentLayer[0];
  }

  /**
   * Generates a Merkle inclusion proof for a specific leaf index.
   *
   * @param leafIndex 0-based index of the target leaf.
   * @returns MerkleProof object containing audit trail siblings.
   */
  generateProof(leafIndex: number): MerkleProof {
    if (this.rawLeaves.length === 0) {
      throw new Error('Cannot generate Merkle proof on an empty tree');
    }
    if (leafIndex < 0 || leafIndex >= this.rawLeaves.length) {
      throw new Error(`Leaf index out of bounds: index ${leafIndex}, total leaves ${this.rawLeaves.length}`);
    }

    const siblings: MerkleProofSibling[] = [];
    let idx = leafIndex;

    for (let l = 0; l < this.layers.length - 1; l++) {
      const layer = this.layers[l];
      const isEven = idx % 2 === 0;
      const siblingIdx = isEven ? (idx + 1 < layer.length ? idx + 1 : idx) : idx - 1;

      siblings.push({
        position: isEven ? 'right' : 'left',
        hash: layer[siblingIdx],
      });

      idx = Math.floor(idx / 2);
    }

    return {
      leafIndex,
      leafHash: this.layers[0][leafIndex],
      siblings,
      merkleRoot: this.root,
    };
  }

  /**
   * Verifies an inclusion proof against an expected Merkle root.
   *
   * @param proof The inclusion proof to check.
   * @param expectedRoot The expected root hash (typically from a signed checkpoint).
   * @returns boolean true if proof is mathematically valid, false otherwise.
   */
  static verifyProof(proof: MerkleProof, expectedRoot: string): boolean {
    if (!proof || !proof.siblings || !expectedRoot) {
      return false;
    }

    let currentHash = proof.leafHash;

    for (const sibling of proof.siblings) {
      if (sibling.position === 'left') {
        currentHash = hashInternalNode(sibling.hash, currentHash);
      } else if (sibling.position === 'right') {
        currentHash = hashInternalNode(currentHash, sibling.hash);
      } else {
        return false;
      }
    }

    return currentHash === expectedRoot;
  }
}
