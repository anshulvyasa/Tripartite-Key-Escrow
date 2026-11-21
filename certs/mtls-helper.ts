import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import http from 'node:http';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';

export interface MTLSOptions {
  certsDir?: string;
  enableMTLS?: boolean;
}

export interface ClientIdentity {
  commonName: string;
  organizationalUnit?: string;
  organization?: string;
  fingerprint?: string;
  isMTLSEnabled: boolean;
}

/**
 * Checks whether mTLS is enabled.
 * Defaults to true unless process.env.ENABLE_MTLS is explicitly 'false' or '0',
 * or explicitly overridden in options.
 */
export function isMTLSEnabled(override?: boolean): boolean {
  if (override !== undefined) {
    return override;
  }
  const envVal = process.env.ENABLE_MTLS;
  if (envVal === 'false' || envVal === '0') {
    return false;
  }
  return true;
}

/**
 * Resolves the directory containing the certificates.
 */
export function resolveCertsDir(customDir?: string): string {
  if (customDir && fs.existsSync(customDir)) {
    return path.resolve(customDir);
  }
  if (process.env.CERTS_DIR && fs.existsSync(process.env.CERTS_DIR)) {
    return path.resolve(process.env.CERTS_DIR);
  }

  // Fallback 1: directory of this file if in certs/
  const fileDir = path.dirname(fileURLToPath(import.meta.url));
  if (fs.existsSync(path.join(fileDir, 'ca.crt'))) {
    return fileDir;
  }

  // Fallback 2: certs/ directory relative to current working directory
  const cwdCerts = path.resolve(process.cwd(), 'certs');
  if (fs.existsSync(path.join(cwdCerts, 'ca.crt'))) {
    return cwdCerts;
  }

  return fileDir;
}

/**
 * Loads server options for Node https.createServer.
 *
 * @param serviceName The name of the service (e.g. 'service-provider', 'node-n1', 'node-n2', 'node-n3').
 * @param options Optional overrides for certsDir and enableMTLS.
 */
export function getMTLSServerOptions(
  serviceName: string,
  options?: MTLSOptions
): https.ServerOptions & { isMTLSEnabled: boolean } {
  const enabled = isMTLSEnabled(options?.enableMTLS);
  const certsDir = resolveCertsDir(options?.certsDir);

  if (!enabled) {
    return {
      isMTLSEnabled: false,
      requestCert: false,
      rejectUnauthorized: false,
    };
  }

  const caPath = path.join(certsDir, 'ca.crt');
  const certPath = path.join(certsDir, `${serviceName}.crt`);
  const keyPath = path.join(certsDir, `${serviceName}.key`);

  if (!fs.existsSync(caPath)) {
    throw new Error(`[mTLS] Root CA certificate not found at: ${caPath}`);
  }
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    throw new Error(`[mTLS] Service certificates not found for '${serviceName}' at: ${certPath}`);
  }

  const ca = fs.readFileSync(caPath);
  const cert = fs.readFileSync(certPath);
  const key = fs.readFileSync(keyPath);

  return {
    isMTLSEnabled: true,
    key,
    cert,
    ca,
    requestCert: true,        // Request certificate from connecting clients
    rejectUnauthorized: true, // Reject any client certificate not signed by our Root CA
  };
}

/**
 * Loads client options and creates an https.Agent configured for mTLS.
 *
 * @param clientName The name of the client certificate (e.g. 'client', 'service-provider', 'node-n1').
 * @param options Optional overrides for certsDir and enableMTLS.
 */
export function getMTLSClientOptions(
  clientName: string,
  options?: MTLSOptions
): https.AgentOptions & { isMTLSEnabled: boolean } {
  const enabled = isMTLSEnabled(options?.enableMTLS);
  const certsDir = resolveCertsDir(options?.certsDir);

  if (!enabled) {
    return {
      isMTLSEnabled: false,
      rejectUnauthorized: false,
    };
  }

  const caPath = path.join(certsDir, 'ca.crt');
  const certPath = path.join(certsDir, `${clientName}.crt`);
  const keyPath = path.join(certsDir, `${clientName}.key`);

  if (!fs.existsSync(caPath)) {
    throw new Error(`[mTLS] Root CA certificate not found at: ${caPath}`);
  }
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    throw new Error(`[mTLS] Client certificates not found for '${clientName}' at: ${certPath}`);
  }

  const ca = fs.readFileSync(caPath);
  const cert = fs.readFileSync(certPath);
  const key = fs.readFileSync(keyPath);

  return {
    isMTLSEnabled: true,
    key,
    cert,
    ca,
    rejectUnauthorized: true,
  };
}

/**
 * Creates an https.Agent for outgoing mTLS requests.
 *
 * @param clientName The client certificate name (default 'client').
 * @param options Optional MTLSOptions.
 */
export function createMTLSAgent(
  clientName: string = 'client',
  options?: MTLSOptions
): https.Agent | http.Agent {
  const clientOpts = getMTLSClientOptions(clientName, options);
  if (!clientOpts.isMTLSEnabled) {
    return new http.Agent();
  }
  return new https.Agent(clientOpts);
}

/**
 * Extracts and returns the verified client identity from an incoming TLS request.
 *
 * @param req Incoming HTTP/HTTPS request.
 */
export function getClientIdentity(req: http.IncomingMessage): ClientIdentity {
  const socket = req.socket as tls.TLSSocket;

  // If mTLS is not active on this connection
  if (!socket || typeof socket.getPeerCertificate !== 'function') {
    return {
      commonName: 'anonymous',
      isMTLSEnabled: false,
    };
  }

  const cert = socket.getPeerCertificate();
  if (!cert || Object.keys(cert).length === 0) {
    return {
      commonName: 'unauthenticated',
      isMTLSEnabled: true,
    };
  }

  const cn = Array.isArray(cert.subject?.CN) ? cert.subject.CN[0] : cert.subject?.CN;
  const ou = Array.isArray(cert.subject?.OU) ? cert.subject.OU[0] : cert.subject?.OU;
  const org = Array.isArray(cert.subject?.O) ? cert.subject.O[0] : cert.subject?.O;

  return {
    commonName: cn || 'unknown',
    organizationalUnit: ou,
    organization: org,
    fingerprint: cert.fingerprint256 || cert.fingerprint,
    isMTLSEnabled: true,
  };
}

/**
 * HTTP Middleware helper to enforce allowed client Common Names (CNs) or Organizational Units (OUs).
 *
 * @param allowedIdentities Array of authorized Common Names (e.g. ['trivault-client', 'escrow-node-1']).
 */
export function enforceClientIdentity(allowedIdentities: string[]) {
  return (req: http.IncomingMessage, res: http.ServerResponse, next: () => void) => {
    if (!isMTLSEnabled()) {
      return next();
    }

    const identity = getClientIdentity(req);
    if (!allowedIdentities.includes(identity.commonName)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Forbidden: Unauthorized mTLS identity',
          clientIdentity: identity.commonName,
          allowedIdentities,
        })
      );
      return;
    }

    next();
  };
}
