/**
 * TriVault Interactive Demonstration Dashboard — Client Application
 * Communicates with /api endpoints and updates all 4 panels in real time.
 */

let state = null;
let selectedMerkleIndex = 0;
let pollTimer = null;
let countdownInterval = null;
let setupVaultSnapshot = null;

// Initialize on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  fetchState();
  pollTimer = setInterval(fetchState, 1500);
});

/**
 * Fetches complete snapshot from dashboard backend.
 */
async function fetchState() {
  try {
    const res = await fetch('/api/state');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const nextState = await res.json();
    if (!nextState.client.dataKeyHex && state?.client?.dataKeyHex !== '') {
      setupVaultSnapshot = null;
      document.getElementById('setup-secrets-list').innerHTML = '';
      for (const id of ['setup-password', 'login-password', 'forgot-new-password']) {
        document.getElementById(id).value = '';
      }
      closeModal('modal-setup');
    }
    state = nextState;
    renderAll();
    return state;
  } catch (err) {
    console.warn('Dashboard fetchState error:', err);
    return null;
  }
}

/**
 * Master render function orchestrating all 4 panels, topbar, and emergency banner.
 */
function renderAll() {
  if (!state) return;

  try { renderTopbar(); } catch (e) { console.warn('renderTopbar error:', e); }
  try { renderEmergencyBanner(); } catch (e) { console.warn('renderEmergencyBanner error:', e); }
  try { renderPanel1Client(); } catch (e) { console.warn('renderPanel1Client error:', e); }
  try { renderPanel2SP(); } catch (e) { console.warn('renderPanel2SP error:', e); }
  try { renderPanel3Escrow(); } catch (e) { console.warn('renderPanel3Escrow error:', e); }
  try { renderPanel4Audit(); } catch (e) { console.warn('renderPanel4Audit error:', e); }
}

// =============================================================================
// TOPBAR & EMERGENCY ALERT BANNER
// =============================================================================
function renderTopbar() {
  if (!state) return;

  // SP Status Pill
  const spDot = document.querySelector('#pill-sp-status .status-dot');
  const spText = document.getElementById('topbar-sp-text');
  if (spDot && spText && state.serviceProvider) {
    if (state.serviceProvider.isOnline) {
      spDot.className = 'status-dot online';
      spText.innerText = 'ONLINE';
    } else {
      spDot.className = 'status-dot offline';
      spText.innerText = 'OFFLINE';
    }
  }

  // Escrow Status Pill
  const escrowDot = document.querySelector('#pill-escrow-status .status-dot');
  const escrowText = document.getElementById('topbar-escrow-text');
  if (escrowDot && escrowText && state.escrowCluster) {
    const onlineCount = state.escrowCluster.onlineCount || 0;
    if (onlineCount >= 2) {
      escrowDot.className = 'status-dot online';
      escrowText.innerText = `${onlineCount}/3 NODES`;
    } else {
      escrowDot.className = 'status-dot offline';
      escrowText.innerText = `${onlineCount}/3 (FAULT)`;
    }
  }

  // Audit Status Pill
  const auditDot = document.querySelector('#pill-audit-status .status-dot');
  const auditText = document.getElementById('topbar-audit-text');
  if (auditDot && auditText && state.auditVerification) {
    if (state.auditVerification.chainValid && state.auditVerification.checkpointValid) {
      auditDot.className = 'status-dot online';
      auditText.innerText = 'VERIFIED';
    } else {
      auditDot.className = 'status-dot offline';
      auditText.innerText = 'TAMPERED';
    }
  }
}

function renderEmergencyBanner() {
  const banner = document.getElementById('emergency-banner');
  if (!banner) return;
  const session = state?.client?.activeRecoverySession;

  if (session && session.status === 'PENDING_DELAY') {
    banner.classList.remove('hidden');
    const desc = document.getElementById('banner-desc');
    if (desc) {
      desc.innerText = `Target Vault: ${session.vaultId} | Type: ${session.recoveryType} | Initiated: 198.51.100.44 | Timelock Window Active`;
    }

    // Live Countdown
    updateBannerCountdown(session.delayExpiresAt);
  } else {
    banner.classList.add('hidden');
    if (countdownInterval) {
      clearInterval(countdownInterval);
      countdownInterval = null;
    }
  }
}

function updateBannerCountdown(expiresAt) {
  const digits = document.getElementById('banner-countdown');
  const diff = expiresAt - Date.now();

  if (diff <= 0) {
    digits.innerText = '00:00 (Ready)';
    // Trigger auto-completion if not already completed
    completeRecovery();
    return;
  }

  const secs = Math.ceil(diff / 1000);
  const m = Math.floor(secs / 60).toString().padStart(2, '0');
  const s = (secs % 60).toString().padStart(2, '0');
  digits.innerText = `${m}:${s}`;
}

// =============================================================================
// PANEL 1: CLIENT & ANDROID SIMULATOR
// =============================================================================
function renderPanel1Client() {
  if (!state?.client) return;
  const client = state.client;
  const loseKeyButton = document.getElementById('btn-lose-key');
  if (loseKeyButton) loseKeyButton.disabled = !client.dataKeyHex;

  // Mode Buttons
  const btnRec = document.getElementById('btn-mode-recoverable');
  const btnStrict = document.getElementById('btn-mode-strict');
  if (client.recoveryMode === 'STRICT') {
    btnStrict.className = 'active';
    btnRec.className = '';
  } else {
    btnRec.className = 'active';
    btnStrict.className = '';
  }

  // Hardware Hooks
  document.getElementById('hook-biometric').checked = client.deviceHooks.biometricOk;
  document.getElementById('hook-device-id').checked = client.deviceHooks.registeredDevice;
  document.getElementById('hook-new-device').checked = client.deviceHooks.isNewDevice;

  // Local Keys
  // Master Password (User Secret)
  const clientPwEl = document.getElementById('client-password');
  if (clientPwEl) {
    if (clientPwEl.dataset.revealed === 'true') {
      clientPwEl.innerText = client.password || '[Not Cached]';
    } else {
      clientPwEl.innerText = client.password ? '••••••••••••' : '[Not Cached]';
    }
  }

  // Password-Derived Key (K_pw — Argon2id)
  const clientKpwEl = document.getElementById('client-kpw');
  if (clientKpwEl) {
    if (client.passwordKeyHex) {
      clientKpwEl.innerText = `${client.passwordKeyHex.slice(0, 16)}...${client.passwordKeyHex.slice(-8)}`;
      clientKpwEl.className = 'key-value mono text-cyan';
    } else {
      clientKpwEl.innerText = '[Not Derived]';
      clientKpwEl.className = 'key-value mono text-dim';
    }
  }

  document.getElementById('client-kdata').innerText = client.dataKeyHex
    ? `${client.dataKeyHex.slice(0, 16)}...${client.dataKeyHex.slice(-8)}`
    : '[Missing — recover or log in]';
  document.getElementById('client-krec').innerText = client.recoveryKeyHex
    ? `${client.recoveryKeyHex.slice(0, 16)}...${client.recoveryKeyHex.slice(-8)}`
    : '[Unloaded]';

  const shareUEl = document.getElementById('client-share-u');
  if (client.deviceHooks.isNewDevice) {
    shareUEl.innerText = '⚠️ LOST (Device Lost / Wipe)';
    shareUEl.className = 'key-value mono text-danger';
  } else if (client.userShare) {
    shareUEl.innerText = `id: ${client.userShare.id} [${client.userShare.data.slice(0, 16)}...]`;
    shareUEl.className = 'key-value mono text-cyan';
  } else {
    shareUEl.innerText = '[Not Initialized]';
    shareUEl.className = 'key-value mono text-dim';
  }

  // Schnorr Identity
  const schnorrPkEl = document.getElementById('client-schnorr-pk');
  if (client.schnorrKeys) {
    schnorrPkEl.innerText = `pk_rec: ${client.schnorrKeys.publicKeyHex.slice(0, 24)}...`;
  } else {
    schnorrPkEl.innerText = 'pk_rec: [Not Generated]';
  }

  // Decrypted & Encrypted Items Rendering (Controlled via Decrypt / Lock Button)
  const itemsContainer = document.getElementById('vault-items-container');
  const badgeVaultStatus = document.getElementById('badge-vault-status');
  const btnDecrypt = document.getElementById('btn-decrypt-vault');
  const btnLock = document.getElementById('btn-lock-vault');
  const indicatorIcon = document.getElementById('vault-indicator-icon');
  const indicatorMsg = document.getElementById('vault-indicator-msg');

  if (client.isVaultUnlocked && Array.isArray(client.decryptedItems)) {
    // UNLOCKED STATE
    if (badgeVaultStatus) {
      badgeVaultStatus.innerText = '🔓 Vault Unlocked';
      badgeVaultStatus.className = 'badge badge-emerald';
    }

    if (btnDecrypt) {
      btnDecrypt.classList.remove('ready-pulse');
      btnDecrypt.disabled = false;
      btnDecrypt.style.opacity = '1';
      btnDecrypt.style.cursor = 'pointer';
      btnDecrypt.setAttribute('title', 'Vault is already unlocked! Click to re-run AES-256-GCM decryption.');
    }

    if (btnLock) {
      btnLock.disabled = false;
      btnLock.style.opacity = '1';
      btnLock.style.cursor = 'pointer';
      btnLock.setAttribute('title', 'Re-lock vault and mask plaintext secrets');
    }

    if (indicatorIcon) indicatorIcon.innerText = '🔓';
    if (indicatorMsg) {
      indicatorMsg.innerHTML = 'Vault decrypted via AES-256-GCM using locally held <strong>K_data</strong>. Plaintext secrets are visible below.';
    }

    itemsContainer.innerHTML = client.decryptedItems
      .map(
        (item) => `
        <div class="vault-item-card unlocked">
          <div class="vault-item-header">
            <span>${escapeHtml(item.title)}</span>
            <div class="item-badges">
              <span class="badge badge-outline">${escapeHtml(item.category)}</span>
              <span class="badge badge-emerald">🔓 Decrypted</span>
            </div>
          </div>
          <div class="vault-item-secret">${escapeHtml(item.secret)}</div>
        </div>
      `
      )
      .join('') || '<p class="text-dim">No secrets yet. Use Manage Secrets to add one.</p>';
  } else {
    // LOCKED / ENCRYPTED STATE
    if (badgeVaultStatus) {
      badgeVaultStatus.innerText = client.dataKeyHex ? '🔒 Vault Locked (Encrypted)' : '🔒 Vault Locked — Key Missing';
      badgeVaultStatus.className = 'badge badge-danger';
    }

    if (btnLock) {
      btnLock.disabled = false;
      btnLock.style.opacity = '0.7';
      btnLock.style.cursor = 'pointer';
      btnLock.setAttribute('title', 'Vault is already locked and masked.');
    }

    if (btnDecrypt) {
      btnDecrypt.disabled = false;
      btnDecrypt.style.opacity = '1';
      btnDecrypt.style.cursor = 'pointer';
    }

    if (client.dataKeyHex) {
      if (btnDecrypt) btnDecrypt.classList.add('ready-pulse');
      if (indicatorIcon) indicatorIcon.innerText = '🔑';
      if (indicatorMsg) {
        indicatorMsg.innerHTML = '<strong>Data Key (K_data) loaded in client keystore!</strong> Click <strong>[ 🔓 Decrypt Vault ]</strong> to perform AES-256-GCM local decryption.';
      }
    } else {
      if (btnDecrypt) btnDecrypt.classList.remove('ready-pulse');
      if (indicatorIcon) indicatorIcon.innerText = '🔒';
      if (indicatorMsg) {
        indicatorMsg.innerHTML = '<strong>K_data is missing from client memory.</strong> Run <strong>Algorithm 2 (U + E)</strong>, wait for recovery to complete, then click <strong>Decrypt Vault</strong>. You can also enter your password using <strong>Algorithm 3 (Login)</strong>.';
      }
    }

    const encItems = client.encryptedItems || [];

    itemsContainer.innerHTML = encItems
      .map(
        (item) => `
        <div class="vault-item-card locked">
          <div class="vault-item-header">
            <span>${escapeHtml(item.title)}</span>
            <div class="item-badges">
              <span class="badge badge-outline">${escapeHtml(item.category)}</span>
              <span class="badge-locked">🔒 Encrypted</span>
            </div>
          </div>
          <div class="vault-item-secret-locked">
            <span class="cipher-preview">${escapeHtml(item.ciphertextPreview)}</span>
            <span class="cipher-hint">🔒 Click [ 🔓 Decrypt Vault ] to unwrap with K_data</span>
          </div>
        </div>
      `
      )
      .join('');
  }
}

// =============================================================================
// PANEL 2: SERVICE PROVIDER (SP) INSPECTOR
// =============================================================================
function renderPanel2SP() {
  if (!state?.serviceProvider) return;
  const sp = state.serviceProvider;

  // SP Offline Toggle
  const toggleSp = document.getElementById('toggle-sp-offline');
  const labelSp = document.getElementById('label-sp-offline');
  toggleSp.checked = sp.isOnline;
  labelSp.innerText = sp.isOnline ? 'SP Online' : 'SP OFFLINE (Simulated)';

  // Storage record
  if (sp.record && sp.isOnline) {
    document.getElementById('sp-vault-id-badge').innerText = sp.record.vaultId;
    document.getElementById('sp-ciphertext').innerText = sp.record.ciphertextPreview;
    document.getElementById('sp-salt').innerText = sp.record.salt;
    document.getElementById('sp-wpw').innerText = `wrappedKey: ${sp.record.wrappedKeyPw.wrappedKey.slice(0, 20)}...`;
    document.getElementById('sp-wrec').innerText = `wrappedKey: ${sp.record.wrappedKeyRec.wrappedKey.slice(0, 20)}...`;
    document.getElementById('sp-share-s').innerText = `id: ${sp.record.spShare.id} [${sp.record.spShare.data.slice(0, 20)}...]`;
  } else if (!sp.isOnline) {
    document.getElementById('sp-vault-id-badge').innerText = 'OFFLINE';
    document.getElementById('sp-ciphertext').innerText = '❌ 503 SERVICE UNAVAILABLE';
    document.getElementById('sp-salt').innerText = '❌ 503 SERVICE UNAVAILABLE';
    document.getElementById('sp-wpw').innerText = '❌ 503 SERVICE UNAVAILABLE';
    document.getElementById('sp-wrec').innerText = '❌ 503 SERVICE UNAVAILABLE';
    document.getElementById('sp-share-s').innerText = '❌ 503 SERVICE UNAVAILABLE';
  } else {
    document.getElementById('sp-vault-id-badge').innerText = 'No Record';
  }

  // Audit list
  const auditList = document.getElementById('sp-audit-list');
  document.getElementById('sp-events-count').innerText = `${sp.auditEvents.length} Events`;
  auditList.innerHTML = sp.auditEvents
    .slice(-5)
    .reverse()
    .map(
      (ev) => `
      <div class="audit-entry-compact">
        <span><strong>#${ev.sequenceNumber}</strong> ${ev.action}</span>
        <span class="mono" style="color: var(--text-dim);">${new Date(ev.timestamp).toLocaleTimeString()}</span>
      </div>
    `
    )
    .join('');
}

// =============================================================================
// PANEL 3: ESCROW CLUSTER & POLICY ENGINE
// =============================================================================
function renderPanel3Escrow() {
  if (!state?.escrowCluster) return;
  const escrow = state.escrowCluster;

  // Node Cards
  ['N1', 'N2', 'N3'].forEach((id) => {
    const node = escrow.nodes[id];
    const dot = document.getElementById(`dot-node-${id.toLowerCase()}`);
    const toggle = document.getElementById(`toggle-node-${id.toLowerCase()}`);
    const val = document.getElementById(`val-node-${id.toLowerCase()}`);

    toggle.checked = node.online;
    if (node.online) {
      dot.className = 'status-dot online';
      val.innerText = node.hasShare ? `${id} (Sub-Share ${node.subShareId} Loaded)` : `${id} (Empty)`;
    } else {
      dot.className = 'status-dot offline';
      val.innerText = 'OFFLINE (Simulated Fault)';
    }
  });

  // Threshold Badge
  const thresholdBadge = document.getElementById('escrow-threshold-badge');
  if (escrow.onlineCount >= 2) {
    thresholdBadge.className = 'badge badge-emerald';
    thresholdBadge.innerText = `${escrow.onlineCount}/3 Nodes Online (Threshold Satisfied)`;
  } else {
    thresholdBadge.className = 'badge badge-danger';
    thresholdBadge.innerText = `${escrow.onlineCount}/3 Nodes Online (FAULT: Threshold Broken)`;
  }

  // Policy Engine Badges
  const session = state.client.activeRecoverySession;
  const isDelayed = session && session.status === 'PENDING_DELAY';
  const hooks = state.client.deviceHooks;

  // WHAT
  const badgeWhat = document.getElementById('badge-factor-what');
  badgeWhat.innerText = state.serviceProvider.record ? 'Vault Registered' : 'Not Found';
  badgeWhat.className = state.serviceProvider.record ? 'badge badge-emerald' : 'badge badge-danger';

  // HOW - Schnorr
  const badgeSchnorr = document.getElementById('badge-factor-schnorr');
  if (isDelayed || session?.status === 'COMPLETED') {
    badgeSchnorr.innerText = 'Verified (pk_rec)';
    badgeSchnorr.className = 'badge badge-emerald';
  } else {
    badgeSchnorr.innerText = 'Awaiting Challenge';
    badgeSchnorr.className = 'badge badge-outline';
  }

  // HOW - Aadhaar
  const badgeAadhaar = document.getElementById('badge-factor-aadhaar');
  if (isDelayed || session?.status === 'COMPLETED') {
    badgeAadhaar.innerText = 'Verified (999988887777)';
    badgeAadhaar.className = 'badge badge-emerald';
  } else {
    badgeAadhaar.innerText = 'Awaiting OTP';
    badgeAadhaar.className = 'badge badge-outline';
  }

  // WHEN
  const badgeWhen = document.getElementById('badge-factor-when');
  if (isDelayed) {
    const diff = Math.max(0, Math.ceil((session.delayExpiresAt - Date.now()) / 1000));
    badgeWhen.innerText = `Delay Active: ${diff}s`;
    badgeWhen.className = 'badge badge-gold';
  } else if (session?.status === 'CANCELLED') {
    badgeWhen.innerText = 'CANCELLED';
    badgeWhen.className = 'badge badge-danger';
  } else {
    badgeWhen.innerText = 'Timer Inactive';
    badgeWhen.className = 'badge badge-outline';
  }

  // Policy Verdict Pill
  const verdictPill = document.getElementById('verdict-pill');
  if (session?.status === 'CANCELLED') {
    verdictPill.className = 'verdict-pill verdict-deny';
    verdictPill.innerText = 'DENIED (Cancelled by User Alert)';
  } else if (isDelayed) {
    verdictPill.className = 'verdict-pill verdict-delay';
    verdictPill.innerText = 'DELAY (Timelock Window Running)';
  } else if (!hooks.biometricOk) {
    verdictPill.className = 'verdict-pill verdict-deny';
    verdictPill.innerText = 'DENIED (Biometric Hook Failed)';
  } else if (!hooks.registeredDevice) {
    verdictPill.className = 'verdict-pill verdict-deny';
    verdictPill.innerText = 'DENIED (Device ID Unrecognized)';
  } else if (escrow.onlineCount < 2) {
    verdictPill.className = 'verdict-pill verdict-deny';
    verdictPill.innerText = 'DENIED (Threshold Not Met)';
  } else {
    verdictPill.className = 'verdict-pill verdict-allow';
    verdictPill.innerText = 'ALLOW — Ready for Access';
  }
}

// =============================================================================
// PANEL 4: AUDIT LOG & MERKLE TREE VERIFIER
// =============================================================================
function renderPanel4Audit() {
  if (!state?.auditVerification || !state?.escrowCluster) return;
  const audit = state.auditVerification;
  const events = state.escrowCluster.auditEvents;
  const banner = document.getElementById('audit-status-banner');
  const bannerIcon = document.getElementById('audit-banner-icon');
  const bannerTitle = document.getElementById('audit-banner-title');
  const bannerDesc = document.getElementById('audit-banner-desc');
  const btnTamper = document.getElementById('btn-tamper-event3');
  const btnRestore = document.getElementById('btn-restore-event3');

  if (audit.tamperedEvent3) {
    banner.className = 'audit-status-banner tampered';
    bannerIcon.innerText = '🚨';
    bannerTitle.innerText = 'TAMPER DETECTED: Hash Chain Broken at Event 3!';
    bannerDesc.innerText =
      'Event 3 payload was mutated without valid signing. prevHash linkage and Merkle root verification failed!';
    btnTamper.classList.add('hidden');
    btnRestore.classList.remove('hidden');
  } else {
    banner.className = 'audit-status-banner';
    bannerIcon.innerText = '✅';
    bannerTitle.innerText = 'Append-Only Hash Chain: Cryptographically Verified';
    bannerDesc.innerText =
      'Every event is immutably linked via SHA-256 hash chains. Signed Merkle checkpoints verified.';
    btnTamper.classList.remove('hidden');
    btnRestore.classList.add('hidden');
  }

  // Merkle Root Badge
  const rootBadge = document.getElementById('badge-merkle-root');
  const checkpoint = state.escrowCluster.latestCheckpoint;
  if (checkpoint) {
    const root = checkpoint.checkpoint.merkleRoot;
    rootBadge.innerText = `Signed Root: ${root.slice(0, 16)}...`;
  } else {
    rootBadge.innerText = 'Root: [Empty]';
  }

  // Merkle Leaves Row
  const leavesRow = document.getElementById('merkle-leaves-row');
  leavesRow.innerHTML = events
    .map(
      (ev, idx) => `
      <div class="merkle-leaf-pill ${idx === selectedMerkleIndex ? 'active' : ''}" onclick="selectMerkleLeaf(${idx})">
        L${idx}: ${ev.action.slice(0, 14)}
      </div>
    `
    )
    .join('');

  // Hash Chain Timeline
  const timeline = document.getElementById('hash-chain-timeline');
  document.getElementById('chain-length-badge').innerText = `${events.length} Blocks`;

  timeline.innerHTML = events
    .map((ev, idx) => {
      const isTamperedBlock = audit.tamperedEvent3 && idx >= 2;
      return `
      <div class="event-block ${isTamperedBlock ? 'tampered-highlight' : ''}">
        <div class="event-block-header">
          <span class="event-seq">#${ev.sequenceNumber}</span>
          <span class="event-action">${ev.action}</span>
          <span class="badge ${isTamperedBlock ? 'badge-danger' : 'badge-outline'}">
            ${isTamperedBlock ? 'TAMPERED / BROKEN' : ev.actor}
          </span>
        </div>
        <div class="event-hashes">
          <span>prev: <strong>${ev.previousHash.slice(0, 12)}...</strong></span>
          <span>→</span>
          <span>curr: <strong class="mono" style="color: ${isTamperedBlock ? 'var(--danger)' : 'var(--cyan)'};">${ev.hash.slice(0, 16)}...</strong></span>
        </div>
      </div>
    `;
    })
    .join('');
}

// =============================================================================
// USER ACTIONS & WORKFLOW HANDLERS
// =============================================================================

async function setVaultMode(mode) {
  try {
    const res = await fetch('/api/client/vault-mode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recoveryMode: mode }),
    });
    const json = await res.json();
    showToast(`Vault Mode set to ${json.recoveryMode}`);
    fetchState();
  } catch (err) {
    showToast(`Failed: ${err.message}`, true);
  }
}

async function updateHooks() {
  const biometricOk = document.getElementById('hook-biometric').checked;
  const registeredDevice = document.getElementById('hook-device-id').checked;
  const isNewDevice = document.getElementById('hook-new-device').checked;

  try {
    await fetch('/api/client/device-hooks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ biometricOk, registeredDevice, isNewDevice }),
    });
    fetchState();
  } catch (err) {
    showToast(`Error: ${err.message}`, true);
  }
}

async function toggleSpOffline() {
  try {
    const res = await fetch('/api/sp/toggle-offline', { method: 'POST' });
    const json = await res.json();
    showToast(`Service Provider is now ${json.spOnline ? 'ONLINE' : 'OFFLINE'}`);
    fetchState();
  } catch (err) {
    showToast(`Error: ${err.message}`, true);
  }
}

async function toggleNode(nodeId) {
  try {
    const res = await fetch('/api/escrow/toggle-node', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nodeId }),
    });
    const json = await res.json();
    showToast(`Node ${nodeId} toggled ${json.nodesOnline[nodeId] ? 'ONLINE' : 'OFFLINE'}`);
    fetchState();
  } catch (err) {
    showToast(`Error: ${err.message}`, true);
  }
}

// Toggle password visibility (show/hide)
function togglePasswordVisibility(target, btnEl) {
  let input = null;
  let button = btnEl;

  if (typeof target === 'string') {
    input = document.getElementById(target);
  } else if (target && target.closest) {
    button = target;
    const wrapper = button.closest('.password-input-wrapper');
    input = wrapper ? wrapper.querySelector('input') : null;
  }
  if (!input) return;

  const isPassword = input.type === 'password';
  input.type = isPassword ? 'text' : 'password';
  const eyeSpan = button.querySelector('.pw-eye-icon') || button;
  eyeSpan.innerText = isPassword ? '🙈' : '👁️';
  button.setAttribute('title', isPassword ? 'Hide Password' : 'Show Password');
}

// Fill current active password into login input
function fillActivePassword() {
  const activePw = state?.client?.password;
  if (!activePw) {
    showToast('The cached password was cleared. Enter your password or use recovery.', true);
    return;
  }
  setLoginPw(activePw);
  showToast(`Filled current password: ${activePw.slice(0, 4)}••••`);
}

// Dynamic Key-Value Secret Rows in Setup Modal
function addSecretRow(key = '', val = '', shouldFocus = true, item = null) {
  const container = document.getElementById('setup-secrets-list');
  if (!container) return;

  const row = document.createElement('div');
  row.className = 'secret-kv-row';
  row.dataset.itemId = item?.id || `item-${crypto.getRandomValues(new Uint32Array(4)).join('-')}`;
  row.dataset.category = item?.category || '';
  row.innerHTML = `
    <input type="text" class="input-text kv-key" placeholder="Key / Label (e.g. Bank PIN, API Key)" value="${escapeHtml(key)}">
    <div class="password-input-wrapper kv-val-wrapper">
      <input type="password" class="input-text kv-val" placeholder="Secret Value" value="${escapeHtml(val)}">
      <button type="button" class="btn-toggle-pw" onclick="togglePasswordVisibility(this)" title="Toggle visibility">
        <span class="pw-eye-icon">👁️</span>
      </button>
    </div>
    <button type="button" class="btn-remove-row" onclick="removeSecretRow(this)" title="Remove item">✕</button>
  `;
  container.appendChild(row);

  if (shouldFocus) {
    // Automatically scroll new row into view so user sees it added immediately
    row.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    const keyInput = row.querySelector('.kv-key');
    if (keyInput) setTimeout(() => keyInput.focus(), 60);
  }
}

function removeSecretRow(btn) {
  const row = btn.closest('.secret-kv-row');
  const container = document.getElementById('setup-secrets-list');
  if (!row || !container) return;

  if (container.querySelectorAll('.secret-kv-row').length > 1) {
    row.remove();
  } else {
    // If only 1 row left, just clear values rather than removing
    const keyInput = row.querySelector('.kv-key');
    const valInput = row.querySelector('.kv-val');
    if (keyInput) keyInput.value = '';
    if (valInput) valInput.value = '';
  }
}

function clearAllSecretRows() {
  const container = document.getElementById('setup-secrets-list');
  if (!container) return;
  container.innerHTML = '';
  addSecretRow('', '', true);
  showToast('Cleared secret rows. Enter your new key-value pairs below.');
}

// Algorithm 1 Setup Modal with state preservation
async function openSetupModal() {
  const modal = document.getElementById('modal-setup');
  if (!modal || !modal.classList.contains('hidden')) return;

  const currentState = await fetchState();
  if (!currentState?.client || !currentState.serviceProvider?.record) {
    showToast('Could not load the current vault. Try opening Manage Secrets again.', true);
    return;
  }
  if (!currentState.client.dataKeyHex) {
    showToast('Recover the data key or log in before editing vault secrets.', true);
    return;
  }
  // Another click may have opened the editor while this request was pending.
  if (!modal.classList.contains('hidden')) return;
  setupVaultSnapshot = {
    vaultId: currentState.client.vaultId,
    iv: currentState.serviceProvider.record.fullCiphertext.iv,
  };

  // Preserve previous state from client
  if (currentState.client) {
    if (currentState.client.vaultId) {
      const vEl = document.getElementById('setup-vault-id');
      if (vEl) vEl.value = currentState.client.vaultId;
    }
    if (currentState.client.password) {
      const pEl = document.getElementById('setup-password');
      if (pEl) pEl.value = currentState.client.password;
    }
    if (currentState.client.recoveryMode) {
      const mEl = document.getElementById('setup-recovery-mode');
      if (mEl) mEl.value = currentState.client.recoveryMode;
    }
  }

  // Populate dynamic secret rows from previous state
  const container = document.getElementById('setup-secrets-list');
  if (container) {
    container.innerHTML = '';
    const activeItems = currentState.client.activeItems || currentState.client.decryptedItems || [];
    if (activeItems.length > 0) {
      activeItems.forEach((item) => {
        addSecretRow(item.title, item.secret || '', false, item);
      });
    } else {
      addSecretRow('', '', false);
    }
  }

  modal.classList.remove('hidden');
}

async function executeSetup() {
  const vaultId = (document.getElementById('setup-vault-id')?.value || '').trim() || 'vault-demo-001';
  const password = document.getElementById('setup-password')?.value || '';
  const recoveryMode = document.getElementById('setup-recovery-mode')?.value || 'RECOVERABLE';

  if (!password) {
    showToast('Enter a master password before initializing the vault.', true);
    document.getElementById('setup-password')?.focus();
    return;
  }

  // Read all dynamic key-value rows
  const rows = document.querySelectorAll('#setup-secrets-list .secret-kv-row');
  const items = [];
  rows.forEach((row, idx) => {
    const key = (row.querySelector('.kv-key')?.value || '').trim();
    const val = row.querySelector('.kv-val')?.value || '';
    if (key || val) {
      let category = 'Personal';
      const lower = key.toLowerCase();
      if (lower.includes('pin') || lower.includes('bank') || lower.includes('card') || lower.includes('finance')) {
        category = 'Finance';
      } else if (lower.includes('btc') || lower.includes('crypto') || lower.includes('mnemonic') || lower.includes('wallet')) {
        category = 'Crypto';
      } else if (lower.includes('ssh') || lower.includes('key') || lower.includes('root') || lower.includes('aws') || lower.includes('api')) {
        category = 'Security';
      }

      items.push({
        id: row.dataset.itemId,
        title: key || `Secret #${idx + 1}`,
        category: row.dataset.category || category,
        secret: val || '',
      });
    }
  });

  try {
    const res = await fetch('/api/vault/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        vaultId,
        password,
        recoveryMode,
        items,
        expectedVaultIv: vaultId === setupVaultSnapshot?.vaultId ? setupVaultSnapshot.iv : null,
      }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    closeModal('modal-setup');
    showToast(`✅ Algorithm 1 Setup Succeeded! Vault initialized & unlocked with ${items.length} secrets.`);
    await fetchState();
  } catch (err) {
    showToast(`Setup Failed: ${err.message}`, true);
  }
}

// Toggle Local Key Inspector Password Visibility
function toggleInspectorPassword(btn) {
  const pwEl = document.getElementById('client-password');
  if (!pwEl) return;
  const isRevealed = pwEl.dataset.revealed === 'true';
  const newRevealed = !isRevealed;
  pwEl.dataset.revealed = newRevealed ? 'true' : 'false';
  const eyeSpan = btn?.querySelector?.('.pw-eye-icon') || btn;
  if (newRevealed) {
    pwEl.innerText = state?.client?.password || '[Not Cached]';
    if (eyeSpan?.innerText) eyeSpan.innerText = '🙈';
    btn?.setAttribute?.('title', 'Hide Password');
  } else {
    pwEl.innerText = '••••••••••••';
    if (eyeSpan?.innerText) eyeSpan.innerText = '👁️';
    btn?.setAttribute?.('title', 'Show Password');
  }
}

// Manual Decrypt Button Trigger
async function triggerManualDecrypt() {
  try {
    const res = await fetch('/api/vault/decrypt', { method: 'POST' });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error);

    showToast('🔓 Vault Decrypted! Plaintext secrets revealed with K_data.');
    fetchState();
  } catch (err) {
    showToast(`Decryption Blocked: ${err.message}`, true);
  }
}

// Manual Lock Button Trigger
async function triggerManualLock(purgeKey = false) {
  try {
    const res = await fetch('/api/vault/lock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ purgeKey }),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error);

    await fetchState();
    showToast(purgeKey
      ? 'Key loss simulated. Run Algorithm 2 to recover K_data, or enter your password using Algorithm 3.'
      : '🔒 Vault Locked! Secrets masked in encrypted state.');
  } catch (err) {
    showToast(`Lock error: ${err.message}`, true);
  }
}

// Algorithm 3 Login
function openLoginModal() {
  const activePw = state?.client?.password || '';
  const loginInput = document.getElementById('login-password');
  if (loginInput) {
    loginInput.value = activePw;
    loginInput.type = 'password';
  }
  const modal = document.getElementById('modal-login');
  if (modal) modal.classList.remove('hidden');
}

function setLoginPw(val) {
  const loginInput = document.getElementById('login-password');
  if (loginInput) loginInput.value = val;
}

async function executeLogin() {
  const password = document.getElementById('login-password')?.value || '';

  try {
    const res = await fetch('/api/vault/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password, autoDecrypt: true }),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error);

    closeModal('modal-login');
    showToast('✅ Login Succeeded! Vault decrypted locally via K_data.');
    fetchState();
  } catch (err) {
    showToast(`Login Rejected: ${err.message}`, true);
  }
}

// Forgot Password (U + S)
function openForgotPasswordModal() {
  document.getElementById('modal-forgot-pw').classList.remove('hidden');
}

async function executeForgotPassword() {
  const newPassword = document.getElementById('forgot-new-password').value;

  try {
    const res = await fetch('/api/vault/forgot-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ newPassword }),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error);

    closeModal('modal-forgot-pw');
    showToast('✅ Password reset with Share U + Share S! Click [ 🔓 Decrypt Vault ] to view plaintext.');
    fetchState();
  } catch (err) {
    showToast(`Forgot Password Failed: ${err.message}`, true);
  }
}

// Algorithm 2: Escrow Recovery (U + E)
async function triggerAlgo2() {
  try {
    const res = await fetch('/api/vault/recover-algo2', { method: 'POST' });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error);

    showToast('Algorithm 2 Initiated! Timelock delay running...');
    fetchState();
  } catch (err) {
    showToast(`Algorithm 2 Denied: ${err.message}`, true);
  }
}

// Algorithm 4: Total Loss Recovery (S + E)
async function triggerAlgo4() {
  try {
    const res = await fetch('/api/vault/recover-algo4', { method: 'POST' });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error);

    showToast('Algorithm 4 Total Loss Initiated! Longest delay active...');
    fetchState();
  } catch (err) {
    showToast(`Algorithm 4 Rejected: ${err.message}`, true);
  }
}

// Complete Recovery
async function completeRecovery() {
  try {
    const res = await fetch('/api/vault/complete-recovery', { method: 'POST' });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error);

    showToast('✅ Recovery Completed! 2-of-3 Shares reconstructed K_data & rotated keys. Click [ 🔓 Decrypt Vault ] to view plaintext!');
    fetchState();
  } catch (err) {
    showToast(`Recovery Failed: ${err.message}`, true);
  }
}

// Cancel Recovery (SIM-Swap defense)
async function cancelRecovery() {
  try {
    const res = await fetch('/api/vault/cancel-recovery', { method: 'POST' });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error);

    showToast('🚨 Recovery request aborted by user! Signed cancellation logged.');
    fetchState();
  } catch (err) {
    showToast(`Cancellation error: ${err.message}`, true);
  }
}

// Tamper Simulator
async function tamperEvent3() {
  try {
    const res = await fetch('/api/audit/tamper-event3', { method: 'POST' });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error);

    showToast('🚨 Event 3 mutated! Chain broken & Merkle verification failed.', true);
    fetchState();
  } catch (err) {
    showToast(`Error: ${err.message}`, true);
  }
}

async function restoreTamper() {
  try {
    const res = await fetch('/api/audit/restore', { method: 'POST' });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error);

    showToast('Audit log restored to pristine state. Verification OK.');
    fetchState();
  } catch (err) {
    showToast(`Error: ${err.message}`, true);
  }
}

// Merkle Leaf Selection
async function selectMerkleLeaf(index) {
  selectedMerkleIndex = index;
  renderPanel4Audit();

  try {
    const res = await fetch(`/api/audit/merkle-proof?index=${index}`);
    const proofData = await res.json();
    if (!res.ok) throw new Error(proofData.error);

    const display = document.getElementById('merkle-proof-display');
    display.classList.remove('hidden');

    display.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-subtle); padding-bottom: 6px;">
        <strong>Merkle Inclusion Proof for Event #${proofData.index} (${proofData.event.action})</strong>
        <span class="badge ${proofData.isValid ? 'badge-emerald' : 'badge-danger'}">
          ${proofData.isValid ? '✓ PROOF VALID (RFC 6962)' : '✕ PROOF MISMATCH'}
        </span>
      </div>
      <div class="proof-step">
        <span class="proof-tag">Leaf Hash</span>
        <span class="mono" style="color: var(--cyan);">${proofData.leafHash}</span>
      </div>
      ${proofData.siblings
        .map(
          (s, i) => `
        <div class="proof-step">
          <span class="proof-tag">Sibling [${s.position}]</span>
          <span class="mono" style="color: var(--gold);">${s.hash}</span>
        </div>
      `
        )
        .join('')}
      <div class="proof-step">
        <span class="proof-tag">Merkle Root</span>
        <span class="mono" style="color: var(--emerald);">${proofData.root}</span>
      </div>
    `;
  } catch (err) {
    console.error('Proof fetch error:', err);
  }
}

// Quick Seed Demo
async function quickSeedDemo() {
  try {
    const res = await fetch('/api/vault/quick-seed', { method: 'POST' });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error);
    showToast('Demo Vault Loaded with Banking PIN, Crypto Mnemonic, and SSH Keys!');
    fetchState();
  } catch (err) {
    showToast(`Error: ${err.message}`, true);
  }
}

// Modal Helpers
function closeModal(id) {
  document.getElementById(id).classList.add('hidden');
}

// Toast Helper
function showToast(msg, isError = false) {
  const toast = document.getElementById('toast');
  const msgEl = document.getElementById('toast-message');

  msgEl.innerText = msg;
  toast.style.borderLeftColor = isError ? 'var(--danger)' : 'var(--cyan)';
  toast.classList.remove('hidden');

  setTimeout(() => {
    toast.classList.add('hidden');
  }, 4000);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
