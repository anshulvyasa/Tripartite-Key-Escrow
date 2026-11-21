import type { ShamirShare } from '@trivault/crypto-core';
import type { NodeId, NodeShareRelease } from './types.ts';

/**
 * Autonomous Escrow Cluster Node (N1, N2, or N3).
 *
 * Invariant:
 * Each node strictly holds only its own Shamir sub-share (Ni).
 * No single node ever holds parent Escrow Share E, User Share U, or SP Share S.
 */
export class EscrowNode {
  public readonly nodeId: NodeId;
  private readonly subShares: Map<string, ShamirShare> = new Map(); // vaultId -> subShare

  constructor(nodeId: NodeId) {
    this.nodeId = nodeId;
  }

  /**
   * Stores the node's assigned Shamir sub-share (N_i).
   * Enforces that the sub-share id corresponds to this node's assigned slot:
   *  N1 -> id: 1
   *  N2 -> id: 2
   *  N3 -> id: 3
   */
  storeSubShare(vaultId: string, subShare: ShamirShare): void {
    const expectedId = this.nodeId === 'N1' ? 1 : this.nodeId === 'N2' ? 2 : 3;
    if (subShare.id !== expectedId) {
      throw new Error(
        `Node ${this.nodeId} expected sub-share id ${expectedId}, but received id ${subShare.id}`
      );
    }
    this.subShares.set(vaultId, subShare);
  }

  /**
   * Releases this node's sub-share only when an authorized recovery policy token is provided.
   */
  releaseSubShare(vaultId: string, authorizationToken: string): NodeShareRelease {
    if (!authorizationToken || authorizationToken.trim().length === 0) {
      throw new Error(`Node ${this.nodeId}: Unauthorized release request (missing authorization token)`);
    }

    const subShare = this.subShares.get(vaultId);
    if (!subShare) {
      throw new Error(`Node ${this.nodeId}: No sub-share found for vault '${vaultId}'`);
    }

    return {
      nodeId: this.nodeId,
      vaultId,
      subShare,
      releasedAt: Date.now(),
    };
  }

  /**
   * Revokes the old sub-share and replaces it with a fresh sub-share during Key Rotation.
   */
  revokeAndReplaceSubShare(vaultId: string, newSubShare: ShamirShare): void {
    this.subShares.delete(vaultId);
    this.storeSubShare(vaultId, newSubShare);
  }

  /**
   * Returns whether the node possesses a sub-share for the target vault.
   */
  hasSubShare(vaultId: string): boolean {
    return this.subShares.has(vaultId);
  }
}
