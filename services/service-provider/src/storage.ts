import type { SPVaultRecord, SetupVaultRequest } from './types.ts';
import { AuditLog } from '@trivault/audit-log';

export class SecurityInvariantViolationError extends Error {
  constructor(message: string) {
    super(`Security Invariant Violation: ${message}`);
    this.name = 'SecurityInvariantViolationError';
  }
}

/**
 * Service Provider Vault Storage with strict zero-knowledge invariant enforcement.
 */
export class VaultStorage {
  private readonly vaults: Map<string, SPVaultRecord> = new Map();
  public readonly auditLog: AuditLog;

  constructor(auditLog?: AuditLog) {
    this.auditLog = auditLog || new AuditLog();
  }

  /**
   * Stores a new vault record, enforcing that no plaintext, raw keys, or extraneous shares are stored.
   */
  createVault(request: SetupVaultRequest, rawPayload?: Record<string, unknown>): SPVaultRecord {
    // Invariant Enforcement 1: Check for forbidden raw plaintext / password fields in raw payload
    if (rawPayload) {
      const forbiddenKeys = ['password', 'plaintext', 'kData', 'kRec', 'userShare', 'escrowShare', 'privateKey'];
      for (const key of forbiddenKeys) {
        if (key in rawPayload && rawPayload[key] !== undefined) {
          throw new SecurityInvariantViolationError(
            `Service Provider must never receive '${key}'. Received unauthorized secret data.`
          );
        }
      }
    }

    // Invariant Enforcement 2: Ensure share is specifically Share S (id: 2)
    if (!request.spShare || request.spShare.id !== 2) {
      throw new SecurityInvariantViolationError(
        `Service Provider must only store Share S (id: 2). Received share id: ${request.spShare?.id}`
      );
    }

    // Invariant Enforcement 3: Validate presence of required wrapped key and ciphertext structures
    if (!request.wrappedKeyPw || !request.wrappedKeyPw.wrappedKey || !request.wrappedKeyPw.iv || !request.wrappedKeyPw.tag) {
      throw new SecurityInvariantViolationError('Missing or malformed wrappedKeyPw.');
    }
    if (!request.wrappedKeyRec || !request.wrappedKeyRec.wrappedKey || !request.wrappedKeyRec.iv || !request.wrappedKeyRec.tag) {
      throw new SecurityInvariantViolationError('Missing or malformed wrappedKeyRec.');
    }
    if (!request.vaultCiphertext || !request.vaultCiphertext.ciphertext || !request.vaultCiphertext.iv || !request.vaultCiphertext.tag) {
      throw new SecurityInvariantViolationError('Missing or malformed vaultCiphertext.');
    }
    if (!request.salt || typeof request.salt !== 'string' || request.salt.length < 16) {
      throw new SecurityInvariantViolationError('Missing or invalid Argon2id salt.');
    }

    if (this.vaults.has(request.vaultId)) {
      throw new Error(`Vault with ID '${request.vaultId}' already exists.`);
    }

    const now = Date.now();
    const recoveryMode = request.recoveryMode || 'RECOVERABLE';
    const record: SPVaultRecord = {
      vaultId: request.vaultId,
      salt: request.salt,
      wrappedKeyPw: request.wrappedKeyPw,
      wrappedKeyRec: request.wrappedKeyRec,
      spShare: request.spShare,
      vaultCiphertext: request.vaultCiphertext,
      recoveryMode,
      createdAt: now,
      updatedAt: now,
    };

    this.vaults.set(request.vaultId, record);

    // Audit Log Entry
    this.auditLog.append('VAULT_SETUP', 'service-provider', {
      vaultId: request.vaultId,
      recoveryMode,
      hasWrappedPw: true,
      hasWrappedRec: true,
      hasSpShare: true,
      spShareId: request.spShare.id,
    });

    return record;
  }

  /**
   * Retrieves login metadata (salt, wrappedKeyPw, vaultCiphertext).
   * Notice: Does not return Share S or wrappedKeyRec.
   */
  getLoginData(vaultId: string): SPVaultRecord {
    const record = this.vaults.get(vaultId);
    if (!record) {
      throw new Error(`Vault with ID '${vaultId}' not found.`);
    }

    this.auditLog.append('VAULT_LOGIN_DATA_RETRIEVED', 'service-provider', { vaultId });
    return record;
  }

  /**
   * Retrieves disaster recovery metadata (wrappedKeyRec, spShare, vaultCiphertext).
   * In Strict Mode, if S+E total loss recovery is attempted, SP strictly denies release.
   */
  getRecoveryData(vaultId: string, requestingSPlusE: boolean = false): SPVaultRecord {
    const record = this.vaults.get(vaultId);
    if (!record) {
      throw new Error(`Vault with ID '${vaultId}' not found.`);
    }

    if (requestingSPlusE && record.recoveryMode === 'STRICT') {
      this.auditLog.append('STRICT_MODE_VIOLATION_BLOCKED', 'service-provider', {
        vaultId,
        reason: 'Attempted S+E total loss recovery on a vault in STRICT mode',
      });
      throw new SecurityInvariantViolationError(
        'Strict Mode Violation: Vault is configured in STRICT mode. Total loss S+E recovery is strictly disabled.'
      );
    }

    this.auditLog.append('VAULT_RECOVERY_DATA_RETRIEVED', 'service-provider', {
      vaultId,
      isSPlusE: requestingSPlusE,
    });
    return record;
  }

  /**
   * Updates password credentials (new Argon2id salt and K_pw-wrapped K_data)
   * used during Forgot Password workflow.
   */
  resetPassword(vaultId: string, salt: string, wrappedKeyPw: SPVaultRecord['wrappedKeyPw']): void {
    const record = this.vaults.get(vaultId);
    if (!record) {
      throw new Error(`Vault with ID '${vaultId}' not found.`);
    }

    if (!wrappedKeyPw || !wrappedKeyPw.wrappedKey || !wrappedKeyPw.iv || !wrappedKeyPw.tag) {
      throw new SecurityInvariantViolationError('Malformed wrappedKeyPw for password reset.');
    }
    if (!salt || typeof salt !== 'string' || salt.length < 16) {
      throw new SecurityInvariantViolationError('Invalid Argon2id salt for password reset.');
    }

    record.salt = salt;
    record.wrappedKeyPw = wrappedKeyPw;
    record.updatedAt = Date.now();

    this.auditLog.append('PASSWORD_RESET', 'service-provider', {
      vaultId,
      timestamp: record.updatedAt,
    });
  }

  /**
   * Replaces old Share S and old wrappedKeyRec with fresh K_rec' artifacts (Key Rotation).
   * Revokes the old Share S on the Service Provider.
   */
  rotateRecoveryKey(
    vaultId: string,
    wrappedKeyRec: SPVaultRecord['wrappedKeyRec'],
    spShare: SPVaultRecord['spShare'],
    salt?: string,
    wrappedKeyPw?: SPVaultRecord['wrappedKeyPw']
  ): void {
    const record = this.vaults.get(vaultId);
    if (!record) {
      throw new Error(`Vault with ID '${vaultId}' not found.`);
    }

    if (!spShare || spShare.id !== 2) {
      throw new SecurityInvariantViolationError('Rotated SP share must have share id: 2');
    }
    if (!wrappedKeyRec || !wrappedKeyRec.wrappedKey || !wrappedKeyRec.iv || !wrappedKeyRec.tag) {
      throw new SecurityInvariantViolationError('Malformed wrappedKeyRec for key rotation.');
    }

    // Revoke old Share S and update wrappedKeyRec
    record.wrappedKeyRec = wrappedKeyRec;
    record.spShare = spShare;

    // Optionally update password credentials if user reset password simultaneously
    if (salt && wrappedKeyPw) {
      record.salt = salt;
      record.wrappedKeyPw = wrappedKeyPw;
    }

    record.updatedAt = Date.now();

    this.auditLog.append('RECOVERY_KEY_ROTATED', 'service-provider', {
      vaultId,
      newSpShareId: spShare.id,
      timestamp: record.updatedAt,
      oldShareRevoked: true,
    });
  }

  /**
   * Updates vault ciphertext for an existing vault.
   */
  updateCiphertext(vaultId: string, ciphertext: SPVaultRecord['vaultCiphertext']): void {
    const record = this.vaults.get(vaultId);
    if (!record) {
      throw new Error(`Vault with ID '${vaultId}' not found.`);
    }

    record.vaultCiphertext = ciphertext;
    record.updatedAt = Date.now();

    this.auditLog.append('VAULT_CIPHERTEXT_UPDATED', 'service-provider', { vaultId });
  }

  /**
   * Checks whether a vault exists.
   */
  hasVault(vaultId: string): boolean {
    return this.vaults.has(vaultId);
  }

  /**
   * Total number of vaults stored.
   */
  get count(): number {
    return this.vaults.size;
  }
}
