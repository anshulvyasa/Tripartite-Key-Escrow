# TriVault (Tripartite Key Escrow) — Agent Architecture & Crypto Specification

This file serves as the definitive reference and persistent memory ("brain") for AI agents, developers, and tools working on the TriVault repository. All architectural choices, cryptographic implementations, and security boundaries must strictly comply with the specifications below.

---

## 1. Project Overview & Repository Structure

TriVault implements a zero-trust, tripartite key escrow system enabling secure data encryption, daily access via password derivation, and resilient recovery via multi-party threshold cryptography and zero-knowledge identity verification.

```
trivault/
├── CLAUDE.md                  # Global architecture rules & crypto specs for the agent
├── docker-compose.yml         # Spins up SP, Escrow Nodes (N1, N2, N3), and Mock Aadhaar
├── packages/
│   ├── crypto-core/           # AES-256-GCM, Argon2id, Shamir 2-of-3, Schnorr signatures
│   └── audit-log/             # Hash chain + Merkle tree + signed root checkpoints
├── certs/                     # Mini CA (PKI) scripts & generated mTLS certificates
├── services/
│   ├── service-provider/      # Hosts vault ciphertext, SP share (S), password-wrapped key
│   ├── escrow-cluster/        # Coordinator + Nodes N1, N2, N3, Policy Engine, Delay Timer
│   └── mock-aadhaar/          # Simulated identity/OTP verification service
├── apps/
│   └── client/                # CLI + Web/Android client (holds Share U + Schnorr privkey)
└── simulations/
    └── game-theory/           # Nash equilibrium & collusion resistance analysis (Objective O5)
```

---

## 2. Key Hierarchy

The cryptographic key hierarchy governs data storage, daily access, and disaster recovery:

1. **Data Key ($K_{\text{data}}$)**:
   - Primitive: Symmetric key for **AES-256-GCM**.
   - Purpose: Directly encrypts and decrypts user vault content/payloads.
   - Lifetime: Generated securely on the client machine; never transmitted in plaintext to any external service.

2. **Password-Derived Key ($K_{\text{pw}}$ — Daily Login)**:
   - Primitive: Derived via **Argon2id** ($\text{Argon2id}(\text{password}, \text{salt})$ with high-memory and iteration parameters).
   - Purpose: Wraps the Data Key for daily user access ($E_{K_{\text{pw}}}(K_{\text{data}})$).
   - Storage: The Service Provider (SP) stores the wrapped key along with the vault ciphertext. The password itself is never transmitted to or stored by the SP.

3. **Recovery Key ($K_{\text{rec}}$ — Disaster Recovery)**:
   - Purpose: Wraps the Data Key for recovery situations ($E_{K_{\text{rec}}}(K_{\text{data}})$).
   - Usage: If the user loses their password, $K_{\text{rec}}$ can be reconstructed to unwrap $K_{\text{data}}$.

---

## 3. Two-Tier Shamir Secret Sharing

Recovery is governed by a hierarchical $(t=2, n=3)$ threshold scheme:

```
                      [Recovery Key: K_rec]
                                |
             ---------------------------------------
            | (t=2, n=3) SSS                        |
            v                                       v
    [User Share: U]                       [SP Share: S]
    (Held locally by client)              (Stored on Service Provider)
            |
            +---------------------------------------+
                                                    v
                                          [Escrow Share: E]
                                                    |
                                 ---------------------------------------
                                | (t=2, n=3) SSS                        |
                                v                   v                   v
                            [Node N1]           [Node N2]           [Node N3]
```

### Tier 1: Tripartite Split
- $K_{\text{rec}}$ is partitioned via Shamir Secret Sharing $(t=2, n=3)$ into three primary shares:
  - **User Share ($U$)**: Stored client-side (e.g., local backup file, secure element, hardware key, paper key).
  - **Service Provider Share ($S$)**: Stored by the Service Provider alongside user metadata.
  - **Escrow Share ($E$)**: Distributed across the independent Escrow Cluster.
- Reconstruction: Any 2 of $\{U, S, E\}$ reconstruct $K_{\text{rec}}$. Any single share reveals zero mathematical information regarding $K_{\text{rec}}$.

### Tier 2: Escrow Cluster Sub-Split
- Escrow Share $E$ is further partitioned via Shamir Secret Sharing $(t=2, n=3)$ across three autonomous Escrow Cluster nodes:
  - **Node 1 Share ($N_1$)**
  - **Node 2 Share ($N_2$)**
  - **Node 3 Share ($N_3$)**
- Reconstruction: At least 2 of $\{N_1, N_2, N_3\}$ must approve and contribute their sub-shares to reconstruct $E$. No single node ever holds $E$ in isolation.

---

## 4. Zero-Knowledge Identity Verification

- **Schnorr Identity Key Pair**:
  - Generated client-side ($sk_{\text{rec}}, pk_{\text{rec}}$).
  - The client retains the private key ($sk_{\text{rec}}$) locally and never discloses it.
  - Only the public key ($pk_{\text{rec}}$) is registered with the Escrow Cluster during account setup.
- **Challenge-Response Authentication**:
  - During key recovery requests, the Escrow Cluster issues a cryptographic challenge (nonce/timestamp).
  - The client signs this challenge using $sk_{\text{rec}}$ via a Schnorr signature.
  - The Escrow nodes verify the signature against $pk_{\text{rec}}$ without acquiring any private credentials or user secrets.

---

## 5. Strict Security Rules & System Invariants

Agents modifying or building components in this repository must maintain the following invariants at all times:

1. **Threshold Secrecy**:
   - Any combination of $k < t$ shares (i.e., 1 share at Tier 1, or 1 sub-share at Tier 2) must mathematically reveal **zero** bits of information about the secret.

2. **Service Provider Zero-Knowledge Boundary**:
   - The Service Provider (SP) only ever observes:
     1. Vault ciphertext.
     2. Wrapped Data Key: $E_{K_{\text{pw}}}(K_{\text{data}})$ and $E_{K_{\text{rec}}}(K_{\text{data}})$.
     3. Its assigned Share $S$.
   - The SP **must never** receive or process:
     - Plaintext vault records.
     - Raw $K_{\text{data}}$ or $K_{\text{rec}}$.
     - Plaintext passwords or client private keys ($sk_{\text{rec}}$).
     - Escrow shares ($E, N_1, N_2, N_3$) or User Share $U$.

3. **Escrow Node Isolation**:
   - Escrow nodes communicate over authenticated mTLS.
   - Node release of sub-shares ($N_i$) is gated strictly by the Policy Engine (e.g., identity verification, mock Aadhaar OTP validation, and timelock delays).

4. **Cryptographic Standards**:
   - Symmetric Cipher: **AES-256-GCM** with fresh, unique 96-bit IV/nonces per encryption operation.
   - Key Derivation: **Argon2id**.
   - Signature Scheme: **Schnorr Signatures** on an approved elliptic curve (e.g., Secp256k1 or Ed25519/Ristretto255).
   - Tamper-evident Auditability: Append-only hash chain and Merkle trees with signed root checkpoints for all recovery and access events.
