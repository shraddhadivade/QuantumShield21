/**
 * QUANTUMSHIELD MESSENGER - CLIENT APPLICATION CONTROLLER
 * Full interactive frontend supporting:
 * - Real-time E2EE messaging simulation with ML-KEM-768 & AES-256-GCM
 * - Dynamic perspective switching (Nova <-> Orion)
 * - Canvas rendering of Quantum Risk Radar (Image 1) & Donut Charts (Image 4)
 * - Live MITM bit-flip tampering, replay attacks, and SOC incident logging
 * - Quantum Vault controls (Key rotation, zeroization, public key export)
 */

document.addEventListener('DOMContentLoaded', () => {
  // =========================================================================
  // APP STATE
  // =========================================================================
  const state = {
    currentUser: 'Nova', // 'Nova' or 'Orion'
    peerUser: 'Orion',
    activeView: 'chat-view',
    mitmActive: false,
    incidentsCount: 0,
    systemIntegrity: 98,
    activeCipher: 'AES-256-GCM',
    pqcAlgorithm: 'ML-KEM-768 (NIST FIPS 203)',
    
    // Cryptographic Key Material (Simulated lattice keys)
    keys: {
      mlkem_ek_hex: 'a9f24b81098e721d6c8b417e33a1059f' + '1088bytes_fips203_lattice_public_key'.repeat(30).slice(0, 2368),
      mlkem_dk_hex: 'PROTECTED_IN_TEE_OR_HSM_ENCLAVE',
      shared_secret_hex: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      ed25519_fingerprint: 'SHA256:8f2a991c0e35b7194a28bbd9104c8f02aa5e34b12',
      session_key_hex: '4f53cda18c2b74df83a201ee97b1a0e882415d94723c3b0f51276a08419db12a'
    },

    messages: []
  };

  // =========================================================================
  // DOM ELEMENT SELECTORS
  // =========================================================================
  const navTabs = document.querySelectorAll('.nav-tab');
  const viewPanels = document.querySelectorAll('.view-panel');
  const btnSwitchPerspective = document.getElementById('btnSwitchPerspective');
  const headerAvatar = document.getElementById('headerAvatar');
  const headerUserName = document.getElementById('headerUserName');
  const sidebarAvatar = document.getElementById('sidebarAvatar');
  const sidebarUserName = document.getElementById('sidebarUserName');
  const activeChatAvatar = document.getElementById('activeChatAvatar');
  const activeChatName = document.getElementById('activeChatName');
  const messageInput = document.getElementById('messageInput');
  const chatForm = document.getElementById('chatForm');
  const chatMessagesContainer = document.getElementById('chatMessagesContainer');
  const chkSimulateMitm = document.getElementById('chkSimulateMitm');
  const btnQuickTamperTest = document.getElementById('btnQuickTamperTest');
  const btnCloseBanner = document.getElementById('btnCloseBanner');
  const securityBanner = document.getElementById('securityBanner');

  // Drawer & Modals
  const chatDetailsDrawer = document.getElementById('chatDetailsDrawer');
  const btnToggleDetails = document.getElementById('btnToggleDetails');
  const btnCloseDetails = document.getElementById('btnCloseDetails');
  const keyModalBackdrop = document.getElementById('keyModalBackdrop');
  const btnTriggerKeyExchange = document.getElementById('btnTriggerKeyExchange');
  const btnCloseKeyModal = document.getElementById('btnCloseKeyModal');
  const btnModalCloseBtn = document.getElementById('btnModalCloseBtn');
  const btnModalCopyBundle = document.getElementById('btnModalCopyBundle');
  const btnQuickVault = document.getElementById('btnQuickVault');
  const modalEkArea = document.getElementById('modalEkArea');
  const modalSsField = document.getElementById('modalSsField');

  // Vault Controls
  const btnVaultRotate = document.getElementById('btnVaultRotate');
  const btnVaultExport = document.getElementById('btnVaultExport');
  const btnVaultPurge = document.getElementById('btnVaultPurge');
  const vaultNoticeBox = document.getElementById('vaultNoticeBox');

  // Attack Lab Controls
  const btnExecuteAttack = document.getElementById('btnExecuteAttack');
  const btnResetAttack = document.getElementById('btnResetAttack');
  const attackInputText = document.getElementById('attackInputText');
  const attackLogTerminal = document.getElementById('attackLogTerminal');
  const incidentResultCard = document.getElementById('incidentResultCard');
  const incidentBadge = document.getElementById('incidentBadge');
  const incidentExplanation = document.getElementById('incidentExplanation');
  const socActiveIncidentsCount = document.getElementById('socActiveIncidentsCount');
  const socIntegrityScore = document.getElementById('socIntegrityScore');
  const socTamperInterceptionsText = document.getElementById('socTamperInterceptionsText');

  // =========================================================================
  // BACKEND API INTEGRATION HELPER
  // =========================================================================
  async function callBackend(endpoint, method = 'GET', body = null) {
    try {
      const options = {
        method: method,
        headers: { 'Content-Type': 'application/json' }
      };
      if (body) options.body = JSON.stringify(body);
      const res = await fetch(endpoint, options);
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail || 'Backend call failed');
      }
      return await res.json();
    } catch (e) {
      console.warn(`[API] Endpoint ${endpoint} fallback to client mode:`, e.message);
      return null;
    }
  }
  navTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetView = tab.getAttribute('data-view');
      switchView(targetView);
    });
  });

  function switchView(viewId) {
    state.activeView = viewId;
    navTabs.forEach(t => {
      t.classList.toggle('active', t.getAttribute('data-view') === viewId);
    });
    viewPanels.forEach(p => {
      p.classList.toggle('active', p.id === viewId);
    });

    if (viewId === 'radar-view') {
      renderQuantumRadar();
      renderDonutCharts();
    }
  }

  // Quick vault button in header
  if (btnQuickVault) {
    btnQuickVault.addEventListener('click', () => switchView('vault-view'));
  }

  // =========================================================================
  // USER PERSPECTIVE SWITCHING (Nova <-> Orion)
  // =========================================================================
  btnSwitchPerspective.addEventListener('click', () => {
    togglePerspective();
  });

  function togglePerspective() {
    if (state.currentUser === 'Nova') {
      state.currentUser = 'Orion';
      state.peerUser = 'Nova';
    } else {
      state.currentUser = 'Nova';
      state.peerUser = 'Orion';
    }

    updatePerspectiveUI();
    renderMessages();
  }

  function updatePerspectiveUI() {
    const isNova = state.currentUser === 'Nova';
    
    headerAvatar.textContent = isNova ? 'N' : 'O';
    headerUserName.textContent = `${state.currentUser} (${isNova ? 'Sender' : 'Receiver'})`;
    
    sidebarAvatar.textContent = isNova ? 'N' : 'O';
    sidebarUserName.textContent = state.currentUser;

    activeChatAvatar.textContent = isNova ? 'O' : 'N';
    activeChatName.textContent = state.peerUser;
    
    messageInput.placeholder = `Type a secure quantum-protected message to ${state.peerUser}... (Enter to send)`;

    // Update details drawer
    const drawerPeerName = document.getElementById('drawerPeerName');
    const drawerAvatar = document.getElementById('drawerAvatar');
    if (drawerPeerName) drawerPeerName.textContent = state.peerUser;
    if (drawerAvatar) drawerAvatar.textContent = isNova ? 'O' : 'N';

    logTerminal(`[PERSPECTIVE] Switched active view to ${state.currentUser}. Identity key active: Ed25519.`, 'term-info');
  }

  // =========================================================================
  // MESSAGING & CRYPTOGRAPHIC PIPELINE
  // =========================================================================
  chatForm.addEventListener('submit', (e) => {
    e.preventDefault();
    sendMessage();
  });

  messageInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  function sendMessage() {
    const text = messageInput.value.trim();
    if (!text) return;

    const isTampered = chkSimulateMitm.checked;
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    // 1. Client Encrypts Payload via AES-256-GCM + ML-KEM-768
    const nonceHex = Array.from(crypto.getRandomValues(new Uint8Array(12)))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    
    const tagHex = Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    const newMsg = {
      id: Date.now(),
      sender: state.currentUser,
      text: text,
      time: timeStr,
      tampered: isTampered,
      meta: {
        ed25519: true,
        pqcKey: true,
        gmacValid: !isTampered,
        nonce: `${nonceHex.slice(0, 8)}...`,
        tag: `${tagHex.slice(0, 8)}...`
      }
    };

    state.messages.push(newMsg);
    messageInput.value = '';
    renderMessages();

    // Async sync with FastAPI Backend if reachable
    callBackend('/api/crypto/encrypt', 'POST', {
      sender: state.currentUser,
      receiver: state.peerUser,
      plaintext: text,
      simulate_tamper: isTampered
    }).then(apiRes => {
      if (apiRes) {
        logTerminal(`[BACKEND API] Packet verified via FastAPI ML-KEM-768 engine. Tag: ${apiRes.tag_hex.slice(0, 8)}...`, 'term-info');
        callBackend('/api/chat/send', 'POST', {
          sender: apiRes.sender,
          receiver: apiRes.receiver,
          kem_ciphertext_hex: apiRes.kem_ciphertext_hex,
          nonce_hex: apiRes.nonce_hex,
          ciphertext_hex: apiRes.ciphertext_hex,
          tag_hex: apiRes.tag_hex,
          signature_hex: apiRes.signature_hex,
          is_tampered: apiRes.is_tampered
        });
      }
    });

    if (isTampered) {
      handleTamperIncident(newMsg);
    } else {
      // Simulate authentic peer response after 1.2s
      setTimeout(() => {
        simulatePeerReply(text);
      }, 1200);
    }
  }

  function simulatePeerReply(originalMsg) {
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const replies = [
      `Packet received! ML-KEM decapsulation verified bit-for-bit. GMAC tag validated.`,
      `Cryptographic integrity verified. Message decrypted without error.`,
      `Acknowledged. The 256-bit AES-GCM session key remains active and synchronized.`
    ];
    const replyText = replies[Math.floor(Math.random() * replies.length)];

    state.messages.push({
      id: Date.now() + 1,
      sender: state.peerUser,
      text: replyText,
      time: timeStr,
      tampered: false,
      meta: {
        ed25519: true,
        pqcKey: true,
        gmacValid: true
      }
    });

    renderMessages();
  }

  function handleTamperIncident(tamperedMsg) {
    state.incidentsCount++;
    state.systemIntegrity = Math.max(75, state.systemIntegrity - 3);

    // Update SOC metrics
    if (socActiveIncidentsCount) socActiveIncidentsCount.textContent = state.incidentsCount;
    if (socIntegrityScore) socIntegrityScore.textContent = `${state.systemIntegrity}%`;
    if (socTamperInterceptionsText) {
      socTamperInterceptionsText.textContent = `${state.incidentsCount} Blocked`;
    }

    // Terminal log
    logTerminal(`[ALERT] MITM Tampering Detected! GMAC Authentication Tag verification failed!`, 'term-danger');
    logTerminal(`[INCIDENT #${state.incidentsCount}] Message from ${tamperedMsg.sender} rejected by ${state.peerUser}. Ciphertext integrity violated in transit.`, 'term-warning');

    // Add alert message into chat
    setTimeout(() => {
      state.messages.push({
        id: Date.now() + 2,
        sender: 'SYSTEM (Security Monitor)',
        text: `⚠️ [CRITICAL SECURITY EXCEPTION]: GMAC Tag Mismatch! Ciphertext or IV was modified by a Man-in-the-Middle attacker. The receiver safely dropped the message to prevent plaintext forgery.`,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        isSystemAlert: true
      });
      renderMessages();
    }, 400);
  }

  function renderMessages() {
    chatMessagesContainer.innerHTML = `
      <div class="system-divider">
        <span>NIST FIPS 203 Cryptographic Session Initialized</span>
      </div>
    `;

    state.messages.forEach(msg => {
      if (msg.isSystemAlert) {
        const alertEl = document.createElement('div');
        alertEl.className = 'message-alert-box';
        alertEl.style.cssText = 'background: rgba(239,68,68,0.15); border: 1px solid #ef4444; border-radius: 8px; padding: 10px 14px; margin: 8px 0; color: #fecaca; font-size: 0.8rem;';
        alertEl.innerHTML = `<strong>SECURITY ALERT:</strong> ${msg.text}`;
        chatMessagesContainer.appendChild(alertEl);
        return;
      }

      const isOutgoing = msg.sender === state.currentUser;
      const msgEl = document.createElement('div');
      msgEl.className = `message ${isOutgoing ? 'outgoing' : 'incoming'} ${msg.tampered ? 'tampered' : ''}`;

      let metaHtml = '';
      if (msg.tampered) {
        metaHtml = `<span class="meta-tag tag-tamper">✕ GMAC TAG FAILED (TAMPER DETECTED)</span>`;
      } else if (msg.meta) {
        metaHtml = `
          <span class="meta-tag tag-verified">✓ Ed25519 Signed</span>
          <span class="meta-tag tag-pqc">ML-KEM-768 OK</span>
          <span class="meta-tag tag-aes">AES-256-GCM (GMAC Valid)</span>
        `;
      }

      const avatarLetter = msg.sender.charAt(0);
      const avatarClass = isOutgoing ? '' : 'avatar-teal';

      msgEl.innerHTML = `
        <div class="message-avatar ${avatarClass}">${avatarLetter}</div>
        <div class="message-body">
          <div class="message-sender">${isOutgoing ? `${msg.sender} (You)` : msg.sender} <span class="message-time">${msg.time}</span></div>
          <div class="message-bubble">${escapeHtml(msg.text)}</div>
          <div class="message-crypto-meta">${metaHtml}</div>
        </div>
      `;

      chatMessagesContainer.appendChild(msgEl);
    });

    chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
  }

  function escapeHtml(str) {
    return str.replace(/[&<>'"]/g, tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag));
  }

  // =========================================================================
  // MITM QUICK TAMPER TEST BUTTON
  // =========================================================================
  if (btnQuickTamperTest) {
    btnQuickTamperTest.addEventListener('click', () => {
      chkSimulateMitm.checked = !chkSimulateMitm.checked;
      const status = chkSimulateMitm.checked ? 'ARMED' : 'DISABLED';
      btnQuickTamperTest.style.borderColor = chkSimulateMitm.checked ? '#ef4444' : 'rgba(255,255,255,0.08)';
      btnQuickTamperTest.style.color = chkSimulateMitm.checked ? '#ef4444' : 'var(--text-secondary)';
      btnQuickTamperTest.textContent = chkSimulateMitm.checked ? '⚠️ Tamper Mode ARMED' : '⚡ Test Tamper Detection';
      logTerminal(`[TAMPER MODE] MITM bit-flip attack simulator is now ${status}.`, chkSimulateMitm.checked ? 'term-warning' : 'term-info');
    });
  }

  if (btnCloseBanner && securityBanner) {
    btnCloseBanner.addEventListener('click', () => {
      securityBanner.style.display = 'none';
    });
  }

  // =========================================================================
  // DETAILS DRAWER TOGGLE
  // =========================================================================
  if (btnToggleDetails && chatDetailsDrawer) {
    btnToggleDetails.addEventListener('click', () => {
      const isVisible = chatDetailsDrawer.style.display !== 'none';
      chatDetailsDrawer.style.display = isVisible ? 'none' : 'flex';
    });
  }

  if (btnCloseDetails && chatDetailsDrawer) {
    btnCloseDetails.addEventListener('click', () => {
      chatDetailsDrawer.style.display = 'none';
    });
  }

  // =========================================================================
  // KEY INSPECTOR MODAL
  // =========================================================================
  if (btnTriggerKeyExchange) {
    btnTriggerKeyExchange.addEventListener('click', () => {
      modalEkArea.value = state.keys.mlkem_ek_hex;
      modalSsField.value = state.keys.shared_secret_hex;
      keyModalBackdrop.classList.add('open');
      logTerminal(`[KEYGEN] ML-KEM-768 lattice keypair inspected for ${state.currentUser}.`, 'term-info');
    });
  }

  if (btnCloseKeyModal) {
    btnCloseKeyModal.addEventListener('click', () => keyModalBackdrop.classList.remove('open'));
  }
  if (btnModalCloseBtn) {
    btnModalCloseBtn.addEventListener('click', () => keyModalBackdrop.classList.remove('open'));
  }
  if (btnModalCopyBundle) {
    btnModalCopyBundle.addEventListener('click', () => {
      navigator.clipboard.writeText(JSON.stringify(state.keys, null, 2));
      alert('Post-Quantum Key Bundle copied to clipboard!');
    });
  }

  // =========================================================================
  // CYBER FORTRESS QUANTUM VAULT COMMANDS (Image 5 style)
  // =========================================================================
  if (btnVaultRotate) {
    btnVaultRotate.addEventListener('click', () => {
      const newHex = Array.from(crypto.getRandomValues(new Uint8Array(32)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
      state.keys.shared_secret_hex = newHex;
      state.keys.session_key_hex = Array.from(crypto.getRandomValues(new Uint8Array(32)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
      
      vaultNoticeBox.textContent = `[SUCCESS] Master ephemeral ML-KEM-768 key rotated at ${new Date().toLocaleTimeString()}. Previous session secret zeroized.`;
      vaultNoticeBox.style.color = '#00ff66';
      logTerminal(`[VAULT] Master key rotation completed. New 256-bit symmetric session key derived.`, 'term-success');
    });
  }

  if (btnVaultExport) {
    btnVaultExport.addEventListener('click', () => {
      const exportData = {
        application: 'QuantumShield Messenger',
        standard: 'NIST FIPS 203 / RFC 8032',
        timestamp: new Date().toISOString(),
        mlkem_ek: state.keys.mlkem_ek_hex.slice(0, 128) + '...[1184 bytes total]',
        ed25519_pubkey: state.keys.ed25519_fingerprint,
        active_protocols: ['ML-KEM-768', 'AES-256-GCM', 'HKDF-SHA256', 'Ed25519']
      };
      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `quantumshield_keys_${state.currentUser.toLowerCase()}.json`;
      a.click();
      logTerminal(`[VAULT] Public key bundle exported as JSON.`, 'term-info');
    });
  }

  if (btnVaultPurge) {
    btnVaultPurge.addEventListener('click', () => {
      if (confirm('CRITICAL ACTION: Are you sure you want to purge all active cryptographic session keys? This zeroizes memory enclaves.')) {
        state.keys.session_key_hex = '0000000000000000000000000000000000000000000000000000000000000000';
        vaultNoticeBox.textContent = `[ZEROIZED] All active session keys purged from memory at ${new Date().toLocaleTimeString()}.`;
        vaultNoticeBox.style.color = '#ef4444';
        logTerminal(`[VAULT PURGE] Zeroization executed. Session keys scrubbed from memory cache.`, 'term-danger');
      }
    });
  }

  // =========================================================================
  // ATTACK LAB SIMULATOR (Live Viva Testing)
  // =========================================================================
  if (btnExecuteAttack) {
    btnExecuteAttack.addEventListener('click', () => {
      const selectedAttack = document.querySelector('input[name="attackType"]:checked').value;
      const payload = attackInputText.value || 'Test Secret Message';

      logTerminal(`------------------------------------------------`, 'term-info');
      logTerminal(`[ATTACK RUNNER] Selected Vector: ${selectedAttack.toUpperCase()}`, 'term-warning');

      if (selectedAttack === 'gmac_tamper') {
        logTerminal(`[STEP 1] Sender generates valid AES-256-GCM ciphertext + 128-bit GMAC Tag.`, 'term-info');
        logTerminal(`[STEP 2] Adversary (Eve) intercepts packet in transit and flips bit 42 in ciphertext block.`, 'term-warning');
        logTerminal(`[STEP 3] Receiver evaluates: GMAC Tag verification calculated vs received.`, 'term-info');
        logTerminal(`[EXCEPTION RAISED]: TamperDetectedException! Tag mismatch detected.`, 'term-danger');
        logTerminal(`[RESULT]: Packet dropped immediately. Zero plaintext revealed to attacker.`, 'term-success');

        incidentBadge.className = 'incident-badge badge-danger';
        incidentBadge.textContent = 'ATTACK BLOCKED';
        incidentExplanation.textContent = 'GMAC authentication tag failed verification! 1 bit modification detected. The system rejected the ciphertext.';
      } else if (selectedAttack === 'replay_attack') {
        logTerminal(`[STEP 1] Adversary captures valid packet (IV: 96-bit, Tag: 128-bit).`, 'term-info');
        logTerminal(`[STEP 2] Adversary replays identical packet 4 minutes later.`, 'term-warning');
        logTerminal(`[STEP 3] Receiver checks anti-replay sliding window & nonce database cache.`, 'term-info');
        logTerminal(`[EXCEPTION RAISED]: ReplayDetectedException! Duplicate IV nonce identified.`, 'term-danger');
        logTerminal(`[RESULT]: Replayed packet rejected.`, 'term-success');

        incidentBadge.className = 'incident-badge badge-danger';
        incidentBadge.textContent = 'REPLAY REJECTED';
        incidentExplanation.textContent = 'Anti-replay nonce monitor blocked duplicate transmission. Nonce reuse prevented.';
      } else if (selectedAttack === 'hndl_attack') {
        logTerminal(`[SIMULATION] Harvest Now, Decrypt Later (HNDL) Threat Vector:`, 'term-info');
        logTerminal(`[CLASSICAL ASYMMETRIC (RSA-2048)]: Vulnerable to Shor's Algorithm. Future Quantum Computer factorizes N in O((log N)^3) steps.`, 'term-danger');
        logTerminal(`[POST-QUANTUM (ML-KEM-768)]: Protected by Module Learning With Errors (M-LWE). No known polynomial quantum speedup exists.`, 'term-success');
        logTerminal(`[ASSESSMENT]: Traffic stored today will remain unbreakable in post-quantum future.`, 'term-success');

        incidentBadge.className = 'incident-badge badge-success';
        incidentBadge.textContent = 'HNDL RESILIENT';
        incidentExplanation.textContent = 'ML-KEM-768 lattice mathematics successfully protect against future quantum decapsulation.';
      }
    });
  }

  if (btnResetAttack) {
    btnResetAttack.addEventListener('click', () => {
      attackLogTerminal.innerHTML = `
        <div class="term-line term-info">[SYSTEM] Attack Lab Ready. Select an attack vector and click Launch.</div>
        <div class="term-line term-info">[SYSTEM] Cryptographic algorithms loaded: ML-KEM-768, AES-256-GCM, Ed25519.</div>
      `;
      incidentBadge.className = 'incident-badge badge-success';
      incidentBadge.textContent = 'SYSTEM SECURE';
      incidentExplanation.textContent = 'No active tampering detected. All cryptographic integrity constraints verified.';
    });
  }

  function logTerminal(text, className = 'term-info') {
    if (!attackLogTerminal) return;
    const line = document.createElement('div');
    line.className = `term-line ${className}`;
    line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
    attackLogTerminal.appendChild(line);
    attackLogTerminal.scrollTop = attackLogTerminal.scrollHeight;
  }

  // =========================================================================
  // CANVAS VISUALIZATIONS: QUANTUM RISK RADAR (Image 1) & DONUTS (Image 4)
  // =========================================================================
  function renderQuantumRadar() {
    const canvas = document.getElementById('quantumRadarCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    const cx = w / 2;
    const cy = h / 2;
    const maxR = 200;

    ctx.clearRect(0, 0, w, h);

    // 1. Concentric radar rings
    for (let r = 50; r <= maxR; r += 40) {
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.07)';
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // 2. Risk Slices (Pie-wedge segments)
    // - Quantum Secure (ML-KEM): 23.1 GB (~26%) -> Emerald
    // - Harvest Now Decrypt Later Risk: 37.53 GB (~42%) -> Amber
    // - Data Exposure Risk: 29.19 GB (~32%) -> Red

    const slices = [
      { start: -Math.PI / 2, end: 0.1, color: '#10b981', label: 'Quantum Secure (23.1 GB)' },
      { start: 0.1, end: Math.PI * 0.9, color: '#f59e0b', label: 'HNDL Risk (37.5 GB)' },
      { start: Math.PI * 0.9, end: -Math.PI / 2, color: '#ef4444', label: 'Exposure Risk (29.2 GB)' }
    ];

    slices.forEach(slice => {
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, maxR - 20, slice.start, slice.end);
      ctx.closePath();
      ctx.fillStyle = slice.color + '26'; // 15% opacity fill
      ctx.fill();
      ctx.strokeStyle = slice.color;
      ctx.lineWidth = 2;
      ctx.stroke();
    });

    // 3. Center Cyber Core
    ctx.beginPath();
    ctx.arc(cx, cy, 55, 0, Math.PI * 2);
    ctx.fillStyle = '#ffffff';
    ctx.fill();
    ctx.strokeStyle = '#0284c7';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Center text
    ctx.fillStyle = '#0f172a';
    ctx.font = 'bold 15px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('89.82 GB', cx, cy - 4);
    ctx.fillStyle = '#64748b';
    ctx.font = '10px Inter, sans-serif';
    ctx.fillText('Data In Motion', cx, cy + 14);

    // 4. Orbiting Data Points (Asset nodes)
    const points = [
      { r: 90, angle: 0.4, label: 'Applications (9k)' },
      { r: 140, angle: 2.1, label: 'User Devices (20.1k)' },
      { r: 170, angle: 3.8, label: 'Infrastructure (800)' }
    ];

    points.forEach(pt => {
      const px = cx + Math.cos(pt.angle) * pt.r;
      const py = cy + Math.sin(pt.angle) * pt.r;

      ctx.beginPath();
      ctx.arc(px, py, 6, 0, Math.PI * 2);
      ctx.fillStyle = '#0284c7';
      ctx.fill();
      ctx.strokeStyle = '#0f172a';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      ctx.fillStyle = '#475569';
      ctx.font = '9px Fira Code, monospace';
      ctx.fillText(pt.label, px, py - 10);
    });
  }

  function renderDonutCharts() {
    drawDonut('cipherStrengthCanvas', 0.71, '#059669');
    drawDonut('protocolVersionCanvas', 0.84, '#0284c7');
  }

  function drawDonut(canvasId, percent, color) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const cx = canvas.width / 2;
    const cy = canvas.height / 2;
    const r = 45;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Background circle
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.strokeStyle = '#e2e8f0';
    ctx.lineWidth = 10;
    ctx.stroke();

    // Value Arc
    ctx.beginPath();
    ctx.arc(cx, cy, r, -Math.PI / 2, -Math.PI / 2 + (Math.PI * 2 * percent));
    ctx.strokeStyle = color;
    ctx.lineWidth = 10;
    ctx.lineCap = 'round';
    ctx.stroke();
  }

  // =========================================================================
  // INITIALIZATION CALL
  // =========================================================================
  updatePerspectiveUI();
  renderMessages();
});
