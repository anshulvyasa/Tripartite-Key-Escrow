import http from 'node:http';
import https from 'node:https';
import { VaultStorage } from './storage.ts';
import type { SetupVaultRequest, UpdateVaultRequest } from './types.ts';
import { getMTLSServerOptions, isMTLSEnabled } from '@trivault/certs';

export interface ServerConfig {
  enableMTLS?: boolean;
  certsDir?: string;
  storage?: VaultStorage;
}

/**
 * Service Provider HTTP / mTLS Server.
 */
export class ServiceProviderServer {
  public readonly storage: VaultStorage;
  private server: http.Server | https.Server | null = null;
  private readonly config: ServerConfig;

  constructor(config: ServerConfig = {}) {
    this.config = config;
    this.storage = config.storage || new VaultStorage();
  }

  /**
   * Request handler routing endpoints.
   */
  private handleRequest = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const method = req.method?.toUpperCase();
    const pathname = url.pathname;

    res.setHeader('Content-Type', 'application/json');

    // Helper to read JSON request body
    const readJson = async (): Promise<any> => {
      let body = '';
      for await (const chunk of req) {
        body += chunk;
      }
      return body ? JSON.parse(body) : {};
    };

    try {
      // 1. Health check
      if (pathname === '/health' && method === 'GET') {
        res.writeHead(200);
        res.end(JSON.stringify({ status: 'ok', service: 'service-provider', vaultsCount: this.storage.count }));
        return;
      }

      // 2. Algorithm 1: Vault Setup Endpoint
      // POST /api/v1/vault/setup
      if (pathname === '/api/v1/vault/setup' && method === 'POST') {
        const payload = await readJson();
        const record = this.storage.createVault(payload as SetupVaultRequest, payload);
        res.writeHead(201);
        res.end(JSON.stringify({ success: true, vaultId: record.vaultId, createdAt: record.createdAt }));
        return;
      }

      // 3. Algorithm 3: Normal Login Data Fetch
      // GET /api/v1/vault/:vaultId/login-data
      const loginMatch = pathname.match(/^\/api\/v1\/vault\/([^/]+)\/login-data$/);
      if (loginMatch && method === 'GET') {
        const vaultId = decodeURIComponent(loginMatch[1]);
        const record = this.storage.getLoginData(vaultId);
        res.writeHead(200);
        res.end(
          JSON.stringify({
            vaultId: record.vaultId,
            salt: record.salt,
            wrappedKeyPw: record.wrappedKeyPw,
            vaultCiphertext: record.vaultCiphertext,
          })
        );
        return;
      }

      // 4. Disaster Recovery Data Fetch
      // GET /api/v1/vault/:vaultId/recovery-data
      const recoveryMatch = pathname.match(/^\/api\/v1\/vault\/([^/]+)\/recovery-data$/);
      if (recoveryMatch && method === 'GET') {
        const vaultId = decodeURIComponent(recoveryMatch[1]);
        const isSPlusE = url.searchParams.get('mode') === 'S_PLUS_E';
        const record = this.storage.getRecoveryData(vaultId, isSPlusE);
        res.writeHead(200);
        res.end(
          JSON.stringify({
            vaultId: record.vaultId,
            wrappedKeyRec: record.wrappedKeyRec,
            spShare: record.spShare,
            vaultCiphertext: record.vaultCiphertext,
            recoveryMode: record.recoveryMode,
          })
        );
        return;
      }

      // 5. Forgot Password: Reset Password Credentials
      // POST /api/v1/vault/:vaultId/reset-password
      const resetPwMatch = pathname.match(/^\/api\/v1\/vault\/([^/]+)\/reset-password$/);
      if (resetPwMatch && method === 'POST') {
        const vaultId = decodeURIComponent(resetPwMatch[1]);
        const { salt, wrappedKeyPw } = await readJson();
        this.storage.resetPassword(vaultId, salt, wrappedKeyPw);
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, vaultId }));
        return;
      }

      // 6. Algorithm 2 & 4: Rotate Recovery Key & Revoke Old Share S
      // POST /api/v1/vault/:vaultId/rotate-recovery-key
      const rotateRecMatch = pathname.match(/^\/api\/v1\/vault\/([^/]+)\/rotate-recovery-key$/);
      if (rotateRecMatch && method === 'POST') {
        const vaultId = decodeURIComponent(rotateRecMatch[1]);
        const { wrappedKeyRec, spShare, salt, wrappedKeyPw } = await readJson();
        this.storage.rotateRecoveryKey(vaultId, wrappedKeyRec, spShare, salt, wrappedKeyPw);
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, vaultId, rotated: true }));
        return;
      }

      // 7. Update Vault Ciphertext
      // PUT /api/v1/vault/:vaultId/data
      const updateMatch = pathname.match(/^\/api\/v1\/vault\/([^/]+)\/data$/);
      if (updateMatch && method === 'PUT') {
        const vaultId = decodeURIComponent(updateMatch[1]);
        const { vaultCiphertext } = (await readJson()) as UpdateVaultRequest;
        this.storage.updateCiphertext(vaultId, vaultCiphertext);
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, vaultId }));
        return;
      }

      // Route not found
      res.writeHead(404);
      res.end(JSON.stringify({ error: `Route ${method} ${pathname} not found.` }));
    } catch (err: any) {
      const statusCode = err.name === 'SecurityInvariantViolationError' ? 400 : 500;
      res.writeHead(statusCode);
      res.end(JSON.stringify({ error: err.message || 'Internal server error' }));
    }
  };

  /**
   * Starts the Service Provider server listening on a TCP port or IPC pipe.
   */
  start(portOrPipe: number | string): Promise<{ address: string; port?: number }> {
    return new Promise((resolve, reject) => {
      const mtlsActive = isMTLSEnabled(this.config.enableMTLS);

      if (mtlsActive) {
        try {
          const opts = getMTLSServerOptions('service-provider', {
            certsDir: this.config.certsDir,
            enableMTLS: true,
          });
          this.server = https.createServer(opts, this.handleRequest);
        } catch (e) {
          // If certs are not available in this test mode, fallback to HTTP if explicitly disabled
          reject(e);
          return;
        }
      } else {
        this.server = http.createServer(this.handleRequest);
      }

      this.server.on('error', reject);

      if (typeof portOrPipe === 'string') {
        // Listening on Named Pipe / IPC
        this.server.listen(portOrPipe, () => {
          resolve({ address: portOrPipe });
        });
      } else {
        // Listening on TCP port
        this.server.listen(portOrPipe, '127.0.0.1', () => {
          const addr = this.server?.address();
          if (addr && typeof addr === 'object') {
            resolve({ address: '127.0.0.1', port: addr.port });
          } else {
            resolve({ address: '127.0.0.1', port: portOrPipe });
          }
        });
      }
    });
  }

  /**
   * Stops the server, terminating any active connections.
   */
  stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        if ('closeAllConnections' in this.server && typeof (this.server as any).closeAllConnections === 'function') {
          (this.server as any).closeAllConnections();
        }
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }
}
