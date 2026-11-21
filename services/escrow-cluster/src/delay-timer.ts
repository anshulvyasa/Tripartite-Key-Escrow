export interface ActiveTimer {
  requestId: string;
  vaultId: string;
  delayMs: number;
  startedAt: number;
  expiresAt: number;
  cancelled: boolean;
  cancellationReason?: string;
  timeoutHandle?: NodeJS.Timeout;
}

/**
 * Manages the timelock delay window for disaster recovery requests.
 * Allows legitimate users to cancel suspicious or unauthorized recovery attempts during the window.
 */
export class DelayTimer {
  private readonly timers: Map<string, ActiveTimer> = new Map();

  /**
   * Starts a delay timer for an authenticated recovery request.
   */
  startTimer(
    requestId: string,
    vaultId: string,
    delayMs: number,
    onExpire?: (requestId: string) => void
  ): { startedAt: number; expiresAt: number } {
    const startedAt = Date.now();
    const expiresAt = startedAt + delayMs;

    let timeoutHandle: NodeJS.Timeout | undefined;
    if (onExpire && delayMs > 0) {
      timeoutHandle = setTimeout(() => {
        const timer = this.timers.get(requestId);
        if (timer && !timer.cancelled) {
          onExpire(requestId);
        }
      }, delayMs);
    }

    this.timers.set(requestId, {
      requestId,
      vaultId,
      delayMs,
      startedAt,
      expiresAt,
      cancelled: false,
      timeoutHandle,
    });

    return { startedAt, expiresAt };
  }

  /**
   * Cancels an active delay timer.
   */
  cancelTimer(requestId: string, reason: string): boolean {
    const timer = this.timers.get(requestId);
    if (!timer) {
      return false;
    }
    if (timer.cancelled) {
      return false;
    }

    timer.cancelled = true;
    timer.cancellationReason = reason;

    if (timer.timeoutHandle) {
      clearTimeout(timer.timeoutHandle);
      timer.timeoutHandle = undefined;
    }

    return true;
  }

  /**
   * Checks whether the timelock delay has elapsed and the request is uncancelled.
   */
  isElapsed(requestId: string): { elapsed: boolean; cancelled: boolean; remainingMs: number } {
    const timer = this.timers.get(requestId);
    if (!timer) {
      return { elapsed: false, cancelled: false, remainingMs: 0 };
    }

    if (timer.cancelled) {
      return { elapsed: false, cancelled: true, remainingMs: 0 };
    }

    const now = Date.now();
    const remainingMs = Math.max(0, timer.expiresAt - now);
    return {
      elapsed: now >= timer.expiresAt,
      cancelled: false,
      remainingMs,
    };
  }

  /**
   * Cleans up all active timer handles (for server shutdown or testing).
   */
  clear(): void {
    for (const timer of this.timers.values()) {
      if (timer.timeoutHandle) {
        clearTimeout(timer.timeoutHandle);
      }
    }
    this.timers.clear();
  }
}
