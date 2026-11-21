import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export interface ParticipantConfig {
  name: string;
  commonName: string;
  isServer: boolean;
  isClient: boolean;
  sanList: string[]; // e.g. ['DNS:localhost', 'IP:127.0.0.1', 'DNS:service-provider']
}

export const PARTICIPANTS: ParticipantConfig[] = [
  {
    name: 'client',
    commonName: 'trivault-client',
    isServer: false,
    isClient: true,
    sanList: ['DNS:localhost', 'IP:127.0.0.1'],
  },
  {
    name: 'service-provider',
    commonName: 'service-provider',
    isServer: true,
    isClient: true,
    sanList: ['DNS:service-provider', 'DNS:localhost', 'IP:127.0.0.1'],
  },
  {
    name: 'node-n1',
    commonName: 'escrow-node-1',
    isServer: true,
    isClient: true,
    sanList: ['DNS:escrow-node-1', 'DNS:node-n1', 'DNS:localhost', 'IP:127.0.0.1'],
  },
  {
    name: 'node-n2',
    commonName: 'escrow-node-2',
    isServer: true,
    isClient: true,
    sanList: ['DNS:escrow-node-2', 'DNS:node-n2', 'DNS:localhost', 'IP:127.0.0.1'],
  },
  {
    name: 'node-n3',
    commonName: 'escrow-node-3',
    isServer: true,
    isClient: true,
    sanList: ['DNS:escrow-node-3', 'DNS:node-n3', 'DNS:localhost', 'IP:127.0.0.1'],
  },
];

/**
 * Generates the Root CA and all signed mTLS certificates for TriVault.
 */
export function generateAllCerts(targetDir?: string): { success: boolean; certs: string[] } {
  const certsDir = targetDir || path.resolve(path.dirname(fileURLToPath(import.meta.url)));
  fs.mkdirSync(certsDir, { recursive: true });

  console.log(`[Mini CA] Generating certificates in: ${certsDir}`);

  // 1. Create a portable minimal OpenSSL config to bypass missing default system configs
  const baseCnfPath = path.join(certsDir, 'openssl.cnf');
  const baseCnfContent = `
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = TriVault

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,cRLSign,keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
`.trim();
  fs.writeFileSync(baseCnfPath, baseCnfContent, 'utf-8');

  // 2. Generate Root CA Private Key and Certificate
  const caKeyPath = path.join(certsDir, 'ca.key');
  const caCrtPath = path.join(certsDir, 'ca.crt');

  console.log('[Mini CA] Generating Root CA (4096-bit RSA)...');
  execFileSync('openssl', [
    'req',
    '-x509',
    '-new',
    '-newkey',
    'rsa:4096',
    '-nodes',
    '-keyout',
    caKeyPath,
    '-out',
    caCrtPath,
    '-sha256',
    '-days',
    '3650',
    '-subj',
    '/CN=TriVault Root CA/O=TriVault/OU=Security',
    '-config',
    baseCnfPath,
    '-extensions',
    'v3_ca',
  ]);

  const generatedCerts: string[] = ['ca.crt'];

  // 3. Generate and sign certificate for each participant
  for (const p of PARTICIPANTS) {
    console.log(`[Mini CA] Generating mTLS cert for: ${p.name} (CN=${p.commonName})...`);

    const keyPath = path.join(certsDir, `${p.name}.key`);
    const csrPath = path.join(certsDir, `${p.name}.csr`);
    const crtPath = path.join(certsDir, `${p.name}.crt`);
    const extPath = path.join(certsDir, `${p.name}.ext`);

    // Key & CSR
    execFileSync('openssl', [
      'req',
      '-new',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      keyPath,
      '-out',
      csrPath,
      '-subj',
      `/CN=${p.commonName}/O=TriVault/OU=${p.name}`,
      '-config',
      baseCnfPath,
    ]);

    // Build extension file for SANs and KeyUsages
    const ekuList: string[] = [];
    if (p.isServer) ekuList.push('serverAuth');
    if (p.isClient) ekuList.push('clientAuth');

    const extContent = `
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = ${ekuList.join(', ')}
subjectAltName = ${p.sanList.join(',')}
`.trim();

    fs.writeFileSync(extPath, extContent, 'utf-8');

    // Sign with Root CA
    execFileSync('openssl', [
      'x509',
      '-req',
      '-in',
      csrPath,
      '-CA',
      caCrtPath,
      '-CAkey',
      caKeyPath,
      '-CAcreateserial',
      '-out',
      crtPath,
      '-days',
      '825',
      '-sha256',
      '-extfile',
      extPath,
    ]);

    // Verify certificate against CA
    const verifyOutput = execFileSync('openssl', ['verify', '-CAfile', caCrtPath, crtPath])
      .toString()
      .trim();
    console.log(`[Mini CA] Verified ${p.name}.crt: ${verifyOutput}`);

    // Clean up temporary files
    try {
      fs.unlinkSync(csrPath);
      fs.unlinkSync(extPath);
    } catch {}

    generatedCerts.push(`${p.name}.crt`);
  }

  // Clean up CA serial if created in default location
  const srlPath = path.join(certsDir, 'ca.srl');
  if (fs.existsSync(srlPath)) {
    try {
      fs.unlinkSync(srlPath);
    } catch {}
  }

  console.log('[Mini CA] All certificates generated and verified successfully!');
  return { success: true, certs: generatedCerts };
}

// Execute directly if run as main script
const currentFile = fileURLToPath(import.meta.url);
const invokedFile = process.argv[1];
if (invokedFile && path.resolve(invokedFile) === path.resolve(currentFile)) {
  generateAllCerts();
}
