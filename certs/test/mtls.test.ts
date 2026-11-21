import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

import {
  generateAllCerts,
  getMTLSServerOptions,
  getMTLSClientOptions,
  createMTLSAgent,
  getClientIdentity,
  enforceClientIdentity,
  isMTLSEnabled,
} from '../index.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const certsDir = path.resolve(__dirname, '..');

describe('TriVault Mini CA & mTLS Infrastructure', () => {
  before(() => {
    // Ensure all certs are generated and up to date
    generateAllCerts(certsDir);
  });

  // =========================================================================
  // 1. Certificate Files & OpenSSL Verification
  // =========================================================================
  describe('PKI Certificate Validation', () => {
    it('should have generated valid Root CA and participant certificate pairs', () => {
      const requiredFiles = [
        'ca.crt',
        'ca.key',
        'client.crt',
        'client.key',
        'service-provider.crt',
        'service-provider.key',
        'node-n1.crt',
        'node-n1.key',
        'node-n2.crt',
        'node-n2.key',
        'node-n3.crt',
        'node-n3.key',
      ];

      for (const file of requiredFiles) {
        const fullPath = path.join(certsDir, file);
        assert.ok(fs.existsSync(fullPath), `Expected file ${file} to exist in certs directory`);
        assert.ok(fs.statSync(fullPath).size > 0, `File ${file} should not be empty`);
      }
    });

    it('should verify all participant certificates against the Root CA via OpenSSL', () => {
      const caPath = path.join(certsDir, 'ca.crt');
      const participants = ['client', 'service-provider', 'node-n1', 'node-n2', 'node-n3'];

      for (const name of participants) {
        const certPath = path.join(certsDir, `${name}.crt`);
        const verifyOutput = execFileSync('openssl', ['verify', '-CAfile', caPath, certPath])
          .toString()
          .trim();
        assert.match(verifyOutput, /OK$/, `Certificate ${name}.crt should verify successfully against Root CA`);
      }
    });
  });

  // =========================================================================
  // 2. Mutual TLS Server & Client Connection Verification
  // =========================================================================
  describe('Live mTLS Handshake & Identity Extraction', () => {
    let server: https.Server;
    const pipeName = `\\\\.\\pipe\\trivault-mtls-test-${Date.now()}`;

    before((_, done) => {
      const serverOpts = getMTLSServerOptions('service-provider', { certsDir, enableMTLS: true });

      server = https.createServer(serverOpts, (req, res) => {
        const identity = getClientIdentity(req);

        if (req.url === '/secure-endpoint') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok', identity }));
          return;
        }

        if (req.url === '/client-only') {
          enforceClientIdentity(['trivault-client'])(req, res, () => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'authorized', client: identity.commonName }));
          });
          return;
        }

        res.writeHead(404);
        res.end();
      });

      server.listen(pipeName, () => {
        done();
      });
    });

    after((_, done) => {
      server.close(done);
    });

    it('PROVE: client with valid mTLS certificate connects and identity is authenticated', async () => {
      const clientOpts = getMTLSClientOptions('client', { certsDir, enableMTLS: true });

      const response = await new Promise<{ statusCode: number; data: any }>((resolve, reject) => {
        const req = https.request(
          {
            socketPath: pipeName,
            path: '/secure-endpoint',
            method: 'GET',
            ...clientOpts,
          },
          (res) => {
            let body = '';
            res.on('data', (chunk) => (body += chunk));
            res.on('end', () => resolve({ statusCode: res.statusCode || 0, data: JSON.parse(body) }));
          }
        );
        req.on('error', reject);
        req.end();
      });

      assert.strictEqual(response.statusCode, 200);
      assert.strictEqual(response.data.status, 'ok');
      assert.strictEqual(response.data.identity.commonName, 'trivault-client');
      assert.strictEqual(response.data.identity.isMTLSEnabled, true);
    });

    it('PROVE: escrow node N1 with valid mTLS certificate connects and is authenticated', async () => {
      const n1Opts = getMTLSClientOptions('node-n1', { certsDir, enableMTLS: true });

      const response = await new Promise<{ statusCode: number; data: any }>((resolve, reject) => {
        const req = https.request(
          {
            socketPath: pipeName,
            path: '/secure-endpoint',
            method: 'GET',
            ...n1Opts,
          },
          (res) => {
            let body = '';
            res.on('data', (chunk) => (body += chunk));
            res.on('end', () => resolve({ statusCode: res.statusCode || 0, data: JSON.parse(body) }));
          }
        );
        req.on('error', reject);
        req.end();
      });

      assert.strictEqual(response.statusCode, 200);
      assert.strictEqual(response.data.identity.commonName, 'escrow-node-1');
    });

    it('PROVE: unauthenticated client without certificate is REJECTED at handshake', async () => {
      const caCert = fs.readFileSync(path.join(certsDir, 'ca.crt'));

      await assert.rejects(
        () =>
          new Promise((resolve, reject) => {
            const req = https.request(
              {
                socketPath: pipeName,
                path: '/secure-endpoint',
                method: 'GET',
                ca: caCert,
                rejectUnauthorized: true,
                // NO CLIENT CERT
              },
              (res) => resolve(res.statusCode)
            );
            req.on('error', reject);
            req.end();
          }),
        (err: any) => {
          // Handshake fails because server enforces client certificate
          return (
            err.code === 'ECONNRESET' ||
            err.code === 'ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED' ||
            err.code === 'ERR_SSL_PEER_DID_NOT_RETURN_A_CERTIFICATE' ||
            err.message.includes('socket hang up') ||
            err.message.includes('alert certificate required') ||
            err.message.includes('certificate required')
          );
        }
      );
    });

    it('PROVE: enforceClientIdentity middleware permits authorized CN and rejects other CNs', async () => {
      // 1. Client CN 'trivault-client' is allowed
      const clientOpts = getMTLSClientOptions('client', { certsDir, enableMTLS: true });
      const allowedRes = await new Promise<number>((resolve, reject) => {
        const req = https.request(
          {
            socketPath: pipeName,
            path: '/client-only',
            method: 'GET',
            ...clientOpts,
          },
          (res) => resolve(res.statusCode || 0)
        );
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(allowedRes, 200);

      // 2. Node CN 'escrow-node-1' is rejected with 403 Forbidden on client-only route
      const n1Opts = getMTLSClientOptions('node-n1', { certsDir, enableMTLS: true });
      const forbiddenRes = await new Promise<{ statusCode: number; data: any }>((resolve, reject) => {
        const req = https.request(
          {
            socketPath: pipeName,
            path: '/client-only',
            method: 'GET',
            ...n1Opts,
          },
          (res) => {
            let body = '';
            res.on('data', (chunk) => (body += chunk));
            res.on('end', () => resolve({ statusCode: res.statusCode || 0, data: JSON.parse(body) }));
          }
        );
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(forbiddenRes.statusCode, 403);
      assert.strictEqual(forbiddenRes.data.clientIdentity, 'escrow-node-1');
    });
  });

  // =========================================================================
  // 3. ENABLE_MTLS Flag Verification
  // =========================================================================
  describe('ENABLE_MTLS Flag Control', () => {
    it('should respect isMTLSEnabled flag and environment variable', () => {
      assert.strictEqual(isMTLSEnabled(true), true);
      assert.strictEqual(isMTLSEnabled(false), false);

      const originalEnv = process.env.ENABLE_MTLS;
      try {
        process.env.ENABLE_MTLS = 'false';
        assert.strictEqual(isMTLSEnabled(), false);

        process.env.ENABLE_MTLS = '0';
        assert.strictEqual(isMTLSEnabled(), false);

        process.env.ENABLE_MTLS = 'true';
        assert.strictEqual(isMTLSEnabled(), true);

        delete process.env.ENABLE_MTLS;
        assert.strictEqual(isMTLSEnabled(), true); // Defaults to true
      } finally {
        process.env.ENABLE_MTLS = originalEnv;
      }
    });

    it('should return unconstrained options when enableMTLS is false', () => {
      const serverOpts = getMTLSServerOptions('service-provider', { enableMTLS: false });
      assert.strictEqual(serverOpts.isMTLSEnabled, false);
      assert.strictEqual(serverOpts.requestCert, false);

      const clientOpts = getMTLSClientOptions('client', { enableMTLS: false });
      assert.strictEqual(clientOpts.isMTLSEnabled, false);
    });
  });
});
