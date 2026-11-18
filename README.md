# QuantumShield Messenger 🔐
## Post-Quantum Secure Messaging & Cryptographic Operations Center

QuantumShield Messenger is a post-quantum end-to-end encrypted (PQ-E2EE) messaging platform engineered for defense against both classical eavesdroppers and future quantum computer attacks (Harvest Now, Decrypt Later).

---

### 1. Cryptographic Architecture
- **Key Establishment:** ML-KEM-768 (NIST FIPS 203 / Kyber-768)
- **Key Derivation:** HKDF-SHA256 (RFC 5869)
- **Payload Encryption:** AES-256-GCM (NIST SP 800-38D) with 128-bit GMAC Authentication Tag
- **Identity & Signatures:** Ed25519 (RFC 8032)
- **Backend API:** FastAPI (Python 3.12)
- **Persistence & Telemetry:** SQLite (WAL Mode)

---

### 2. How to Run Frontend (Stage 2)
To launch the frontend interface:

```powershell
# From the project root
cd C:\Users\shrad\.gemini\antigravity\scratch\QuantumShield
python run_frontend.py
```

Then open your browser at:
`http://127.0.0.1:5500/`

---

### 3. Integrated Interface Modules
1. **💬 Messenger (Session/Slack Aesthetic)**: Real-time chat between Nova (Sender) and Orion (Receiver) with live cryptographic badges.
2. **📡 Quantum Risk Radar (Palo Alto Style)**: Live circular risk posture displaying Data In Motion, HNDL Risk, and ML-KEM protected traffic.
3. **📊 SentinelX SOC (Incident Command Center)**: Real-time threat levels, active GMAC tamper detection counters, and live node topography.
4. **🗝️ Quantum Vault (Cyber Fortress Style)**: Cryptographic key management, master key rotation, public key JSON bundle export, and memory zeroization.
5. **⚡ Attack Simulation Lab (Viva Demonstration)**: Live interactive attacks (Bit-flip GMAC tampering, Nonce replay, and Shor's algorithm HNDL defense).
