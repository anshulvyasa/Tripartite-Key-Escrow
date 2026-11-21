import crypto from 'node:crypto';
import type { AuditEvent, ChainVerificationResult } from './types.ts';

export const GENESIS_PREV_HASH = '0'.repeat(64);

/**
 * Deterministically sorts object keys for canonical serialization.
 */
function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalStringify).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const entries = sortedKeys.map((k) => `${JSON.stringify(k)}:${canonicalStringify(obj[k])}`);
  return `{${entries.join(',')}}`;
}

/**
 * Computes the canonical SHA-256 hash of an event's data fields (excluding the hash field itself).
 */
export function computeEventHash(
  event: Omit<AuditEvent<any>, 'hash'> & { hash?: string }
): string {
  const canonicalPayload = canonicalStringify({
    action: event.action,
    actor: event.actor,
    index: event.index,
    payload: event.payload,
    prevHash: event.prevHash,
    timestamp: event.timestamp,
  });

  return crypto.createHash('sha256').update(canonicalPayload, 'utf-8').digest('hex');
}

/**
 * Append-only cryptographic hash chain.
 */
export class HashChain {
  private readonly events: AuditEvent[] = [];

  constructor(initialEvents: AuditEvent[] = []) {
    if (initialEvents.length > 0) {
      this.events = initialEvents.map((e) => ({ ...e }));
    }
  }

  /**
   * Appends a new event to the hash chain.
   *
   * @param action Event descriptor (e.g. 'VAULT_INIT', 'RECOVERY_REQUEST').
   * @param actor Initiating entity identifier.
   * @param payload Structured event metadata.
   * @param timestamp Optional epoch millisecond timestamp (defaults to Date.now()).
   * @returns The immutable appended AuditEvent.
   */
  append<T = Record<string, unknown>>(
    action: string,
    actor: string,
    payload: T,
    timestamp: number = Date.now()
  ): AuditEvent<T> {
    const index = this.events.length;
    const prevHash = index === 0 ? GENESIS_PREV_HASH : this.events[index - 1].hash;

    const baseEvent = {
      index,
      timestamp,
      action,
      actor,
      payload,
      prevHash,
    };

    const hash = computeEventHash(baseEvent);

    const event: AuditEvent<T> = {
      ...baseEvent,
      hash,
    };

    this.events.push(event as AuditEvent<Record<string, unknown>>);
    return event;
  }

  /**
   * Returns a shallow copy array of all events in the chain.
   */
  getEvents(): ReadonlyArray<AuditEvent> {
    return [...this.events];
  }

  /**
   * Returns the event at the specified sequence index.
   */
  getEvent(index: number): AuditEvent | undefined {
    return this.events[index];
  }

  /**
   * Returns the most recent event at the head of the chain.
   */
  getHead(): AuditEvent | undefined {
    return this.events[this.events.length - 1];
  }

  /**
   * Returns the SHA-256 hash of the head event (or genesis hash if empty).
   */
  getHeadHash(): string {
    const head = this.getHead();
    return head ? head.hash : GENESIS_PREV_HASH;
  }

  /**
   * Number of events currently recorded in the chain.
   */
  get length(): number {
    return this.events.length;
  }

  /**
   * Verifies the cryptographic integrity of the entire hash chain from genesis to head.
   * Checks sequential indexing, previous hash continuity, and SHA-256 content hashes.
   */
  verifyIntegrity(): ChainVerificationResult {
    const totalEvents = this.events.length;

    for (let i = 0; i < totalEvents; i++) {
      const event = this.events[i];

      // 1. Verify sequence index
      if (event.index !== i) {
        return {
          valid: false,
          totalEvents,
          brokenIndex: i,
          reason: `Sequence index mismatch at position ${i}: event.index is ${event.index}`,
        };
      }

      // 2. Verify previous hash linkage
      const expectedPrevHash = i === 0 ? GENESIS_PREV_HASH : this.events[i - 1].hash;
      if (event.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          totalEvents,
          brokenIndex: i,
          reason: `Previous hash mismatch at index ${i}: expected ${expectedPrevHash}, found ${event.prevHash}`,
        };
      }

      // 3. Verify event content hash
      const computedHash = computeEventHash(event);
      if (event.hash !== computedHash) {
        return {
          valid: false,
          totalEvents,
          brokenIndex: i,
          reason: `Content hash mismatch at index ${i}: computed ${computedHash}, stored ${event.hash} (tampered payload/metadata)`,
        };
      }
    }

    return {
      valid: true,
      totalEvents,
    };
  }
}
