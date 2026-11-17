import crypto from 'node:crypto';
import type { ShamirShare, TopLevelShares, EscrowSubShares } from './types.ts';

/**
 * Custom error thrown when an insufficient threshold of shares is provided.
 */
export class InsufficientSharesError extends Error {
  constructor(message: string = 'Insufficient shares: threshold is 2, but fewer than 2 shares were provided.') {
    super(message);
    this.name = 'InsufficientSharesError';
  }
}

/**
 * Custom error thrown when a share is malformed or invalid.
 */
export class InvalidShareError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidShareError';
  }
}

// Precomputed GF(2^8) tables using generator 3 and irreducible polynomial 0x11b
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);

(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    EXP[i + 255] = x;
    LOG[x] = i;
    const next = (x << 1) ^ (x & 0x80 ? 0x11b : 0);
    x = next ^ x; // multiply by 3 = (x * 2) ^ x
  }
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error('GF(2^8) division by zero');
  if (a === 0) return 0;
  return EXP[(LOG[a] - LOG[b] + 255) % 255];
}

/**
 * Low-level 2-of-3 Shamir Secret Sharing split over GF(2^8).
 * Takes an arbitrary byte secret and generates 3 shares (x=1, x=2, x=3).
 *
 * @param secret The secret bytes to split (e.g. 32-byte key).
 * @returns Tuple of 3 ShamirShare objects.
 */
export function splitSecret2of3(secret: Uint8Array): [ShamirShare, ShamirShare, ShamirShare] {
  if (secret.length === 0) {
    throw new Error('Secret cannot be empty');
  }

  const len = secret.length;
  const share1Bytes = new Uint8Array(len);
  const share2Bytes = new Uint8Array(len);
  const share3Bytes = new Uint8Array(len);

  // Random slope coefficients a1 for each byte in secret
  const randomCoeffs = crypto.randomBytes(len);

  for (let i = 0; i < len; i++) {
    const a0 = secret[i];
    // Ensure non-zero random slope for maximum entropy
    let a1 = randomCoeffs[i];
    if (a1 === 0) a1 = 1;

    // Polynomial f(x) = a0 ^ (a1 * x)
    // x = 1: f(1) = a0 ^ (a1 * 1)
    share1Bytes[i] = a0 ^ gfMul(a1, 1);
    // x = 2: f(2) = a0 ^ (a1 * 2)
    share2Bytes[i] = a0 ^ gfMul(a1, 2);
    // x = 3: f(3) = a0 ^ (a1 * 3)
    share3Bytes[i] = a0 ^ gfMul(a1, 3);
  }

  return [
    { id: 1, data: Buffer.from(share1Bytes).toString('hex') },
    { id: 2, data: Buffer.from(share2Bytes).toString('hex') },
    { id: 3, data: Buffer.from(share3Bytes).toString('hex') },
  ];
}

/**
 * Reconstructs a secret from any 2 distinct shares using Lagrange interpolation over GF(2^8).
 *
 * @param shares Array of ShamirShare objects. Must contain at least 2 shares with unique IDs.
 * @returns Reconstructed secret as Uint8Array.
 * @throws InsufficientSharesError if fewer than 2 shares are supplied.
 * @throws InvalidShareError if duplicate share IDs or mismatched lengths are detected.
 */
export function reconstructSecret2of3(shares: ShamirShare[]): Uint8Array {
  if (!shares || shares.length < 2) {
    throw new InsufficientSharesError(
      `Insufficient shares: threshold is 2, but received ${shares ? shares.length : 0} share(s). A single share reveals zero information.`
    );
  }

  // Deduplicate by ID
  const uniqueShares = new Map<number, ShamirShare>();
  for (const s of shares) {
    if (!uniqueShares.has(s.id)) {
      uniqueShares.set(s.id, s);
    }
  }

  if (uniqueShares.size < 2) {
    throw new InvalidShareError('At least 2 shares with distinct IDs (x-coordinates) are required.');
  }

  const [shareA, shareB] = Array.from(uniqueShares.values());

  const bytesA = Buffer.from(shareA.data, 'hex');
  const bytesB = Buffer.from(shareB.data, 'hex');

  if (bytesA.length !== bytesB.length) {
    throw new InvalidShareError(`Share byte length mismatch: ${bytesA.length} vs ${bytesB.length}`);
  }

  const xA = shareA.id;
  const xB = shareB.id;

  if (xA < 1 || xA > 255 || xB < 1 || xB > 255 || xA === xB) {
    throw new InvalidShareError(`Invalid or duplicate x-coordinates: xA=${xA}, xB=${xB}`);
  }

  // Lagrange basis polynomials evaluated at x = 0:
  // lA(0) = (0 - xB) / (xA - xB) = xB / (xA ^ xB) in GF(2^8)
  // lB(0) = (0 - xA) / (xB - xA) = xA / (xA ^ xB) in GF(2^8)
  const denom = xA ^ xB;
  const lA = gfDiv(xB, denom);
  const lB = gfDiv(xA, denom);

  const secret = new Uint8Array(bytesA.length);
  for (let i = 0; i < bytesA.length; i++) {
    secret[i] = gfMul(lA, bytesA[i]) ^ gfMul(lB, bytesB[i]);
  }

  return secret;
}

/**
 * Top-Level Recovery Key Splitting:
 * Splits the Recovery Key (K_rec) into User Share (U), SP Share (S), and Escrow Share (E).
 *
 * @param kRec 32-byte recovery key.
 * @returns TopLevelShares containing { userShare (id: 1), spShare (id: 2), escrowShare (id: 3) }.
 */
export function splitRecoveryKey(kRec: Uint8Array): TopLevelShares {
  const [userShare, spShare, escrowShare] = splitSecret2of3(kRec);
  return {
    userShare,   // Share U
    spShare,     // Share S
    escrowShare, // Share E
  };
}

/**
 * Reconstructs the Recovery Key (K_rec) from any 2 of {User Share U, SP Share S, Escrow Share E}.
 */
export function reconstructRecoveryKey(shares: ShamirShare[]): Uint8Array {
  return reconstructSecret2of3(shares);
}

/**
 * Escrow Cluster Sub-Splitting:
 * Splits the Escrow Share (E) into 3 node sub-shares (N1, N2, N3) distributed across independent nodes.
 *
 * @param escrowShare Escrow Share E (either ShamirShare or raw Uint8Array).
 * @returns EscrowSubShares containing { n1Share (id: 1), n2Share (id: 2), n3Share (id: 3) }.
 */
export function splitEscrowShare(escrowShare: ShamirShare | Uint8Array): EscrowSubShares {
  const rawBytes = 'data' in escrowShare ? Buffer.from(escrowShare.data, 'hex') : escrowShare;
  const [n1Share, n2Share, n3Share] = splitSecret2of3(rawBytes);
  return {
    n1Share,
    n2Share,
    n3Share,
  };
}

/**
 * Reconstructs the Escrow Share (E, id: 3) from any 2 of {N1, N2, N3}.
 *
 * @param subShares Array containing at least 2 node sub-shares.
 * @returns Reconstructed Escrow Share (E) with id: 3.
 */
export function reconstructEscrowShare(subShares: ShamirShare[]): ShamirShare {
  const rawE = reconstructSecret2of3(subShares);
  return {
    id: 3, // Escrow Share E's coordinate in the top-level split
    data: Buffer.from(rawE).toString('hex'),
  };
}

/**
 * End-to-End Hierarchical Recovery Helper:
 * Combines one primary share (User Share U or SP Share S) with any 2 Escrow cluster sub-shares (N_i, N_j)
 * to reconstruct K_rec in a single operation.
 *
 * @param primaryShare Either User Share U (id: 1) or SP Share S (id: 2).
 * @param escrowSubShares At least 2 node sub-shares from {N1, N2, N3}.
 * @returns Reconstructed Recovery Key K_rec.
 */
export function reconstructFromHierarchicalShares(
  primaryShare: ShamirShare,
  escrowSubShares: ShamirShare[]
): Uint8Array {
  // Step 1: Reconstruct Escrow Share E from the node sub-shares
  const reconstructedE = reconstructEscrowShare(escrowSubShares);

  // Step 2: Reconstruct K_rec from primary share + reconstructed E
  return reconstructRecoveryKey([primaryShare, reconstructedE]);
}
