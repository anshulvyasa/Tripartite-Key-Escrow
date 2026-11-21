import http from 'node:http';
import https from 'node:https';
import { EscrowCoordinator } from './coordinator.ts';
import { getMTLSServerOptions, isMTLSEnabled } from '@trivault/certs';

export interface EscrowServerConfig {
  coordinator?: EscrowCoordinator;
  certsDir?: string;
  enableMTLS?: boolean;
}

/**
 * Escrow Cluster HTTP & mTLS Server.
 */
export class EscrowServer {
  public readonly coordinator: EscrowCoordinator;
  private server: http.Server | https.Server | null = null;
  private readonly config: EscrowServerConfig;

  constructor(config: EscrowServerConfig = {}) {
    this.config = config;
    this.coordinator = config.coordinator || new EscrowCoordinator();
  }

  private handleRequest = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const method = req.method?.toUpperCase();
    const pathname = url.pathname;

    res.setHeader('Content-Type', 'application/json');

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
        res.end(JSON.stringify({ status: 'ok', service: 'escrow-cluster', nodes: ['N1', 'N2', 'N3'] }));
        return;
      }

      // 2. Register Vault with Escrow Cluster
      // POST /api/v1/escrow/register
      if (pathname === '/api/v1/escrow/register' && method === 'POST') {
        const { vaultId, escrowShareE, clientPubKeyHex, aadhaarNumber, recoveryMode } = await readJson();
        const checkpoint = this.coordinator.registerVault(
          vaultId,
          escrowShareE,
          clientPubKeyHex,
          aadhaarNumber,
          recoveryMode
        );
        res.writeHead(201);
        res.end(JSON.stringify({ success: true, vaultId, checkpoint }));
        return;
      }

      // 3. Initiate Recovery (Step 1)
      // POST /api/v1/escrow/recovery/initiate
      if (pathname === '/api/v1/escrow/recovery/initiate' && method === 'POST') {
        const { vaultId, recoveryType } = await readJson();
        const initResult = this.coordinator.initiateRecovery(vaultId, recoveryType);
        res.writeHead(200);
        res.end(JSON.stringify(initResult));
        return;
      }

      // 4. Submit Recovery Proof (Step 2: Schnorr Signature + Aadhaar OTP)
      // POST /api/v1/escrow/recovery/submit-proof
      if (pathname === '/api/v1/escrow/recovery/submit-proof' && method === 'POST') {
        const { requestId, schnorrSignatureHex, otp, customDelayMs } = await readJson();
        const proofResult = this.coordinator.submitRecoveryProof(
          requestId,
          schnorrSignatureHex,
          otp,
          customDelayMs
        );
        res.writeHead(200);
        res.end(JSON.stringify(proofResult));
        return;
      }

      // 5. Cancel Recovery
      // POST /api/v1/escrow/recovery/cancel
      if (pathname === '/api/v1/escrow/recovery/cancel' && method === 'POST') {
        const { requestId, reason } = await readJson();
        const checkpoint = this.coordinator.cancelRecovery(requestId, reason || 'User requested abort');
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, status: 'CANCELLED', checkpoint }));
        return;
      }

      // 6. Complete Recovery (Step 3: Collect Sub-Shares after Delay)
      // POST /api/v1/escrow/recovery/complete
      if (pathname === '/api/v1/escrow/recovery/complete' && method === 'POST') {
        const { requestId, nodePair } = await readJson();
        const completeResult = this.coordinator.completeRecovery(requestId, nodePair);
        res.writeHead(200);
        res.end(JSON.stringify(completeResult));
        return;
      }

      // 7. Key Rotation & Share Revocation (Algorithm 2 & 4)
      // POST /api/v1/escrow/rotate
      if (pathname === '/api/v1/escrow/rotate' && method === 'POST') {
        const { vaultId, newEscrowShareE, newClientPubKeyHex } = await readJson();
        const rotateResult = this.coordinator.rotateVaultEscrow(
          vaultId,
          newEscrowShareE,
          newClientPubKeyHex
        );
        res.writeHead(200);
        res.end(JSON.stringify(rotateResult));
        return;
      }

      // Route not found
      res.writeHead(404);
      res.end(JSON.stringify({ error: `Route ${method} ${pathname} not found.` }));
    } catch (err: any) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: err.message || 'Escrow cluster request error' }));
    }
  };

  /**
   * Starts server on TCP port or Named Pipe.
   */
  start(portOrPipe: number | string): Promise<{ address: string; port?: number }> {
    return new Promise((resolve, reject) => {
      const mtlsActive = isMTLSEnabled(this.config.enableMTLS);

      if (mtlsActive) {
        try {
          const opts = getMTLSServerOptions('node-n1', {
            certsDir: this.config.certsDir,
            enableMTLS: true,
          });
          this.server = https.createServer(opts, this.handleRequest);
        } catch (e) {
          reject(e);
          return;
        }
      } else {
        this.server = http.createServer(this.handleRequest);
      }

      this.server.on('error', reject);

      if (typeof portOrPipe === 'string') {
        this.server.listen(portOrPipe, () => {
          resolve({ address: portOrPipe });
        });
      } else {
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

  stop(): Promise<void> {
    this.coordinator.shutdown();
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
