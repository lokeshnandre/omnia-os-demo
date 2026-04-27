# OMNIA-OS — iDARIA™ Hardware-Anchored Trust Protocol

<div align="center">

**iDARIA Foundation | Turin, Italy**

*Eliminating the Trust Tax through silicon-level verification*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--alpha%20%2F%20active%20development-orange.svg)]()
[![Turin Pilot](https://img.shields.io/badge/pilot-Turin%2C%20Italy%202026-green.svg)]()
[![Polygon](https://img.shields.io/badge/chain-Polygon%20Mumbai-purple.svg)]()

[Live Demo Dashboard](#demo) · [Architecture](#architecture) · [Quick Start](#quick-start) · [The Middleman Theory](#the-middleman-theory)

</div>

---

## The Problem: The Global Trust Tax

Every middleman in the global economy exists for exactly one reason: to answer the question **"Can I trust this?"** — and charge rent for the answer.

- Glovo charges **30%** from restaurants to verify a rider delivered food
- Recruiters charge **20-40%** to verify a candidate's work history
- Fraud analysts cost **€120,000/year/FTE** to verify behavioral claims
- Rideshare platforms verify drivers **once, in software, years ago**

Software-layer identity is trivially spoofable. A rider can fake GPS with a $2 app. A driver can rent their Uber account for $65/month. A candidate can lie on a CV. The Trust Tax exists because there was no other way.

**There is now.**

---

## The Solution: Silicon-Level Verification

OMNIA-OS moves the trust verification layer from software (spoofable) to the hardware **Trusted Execution Environment (TEE)** — the same tamper-proof chip that protects your bank fingerprint.

```
GPS Sensor → Custom HAL (C/C++) → TEE / StrongBox → Signed Attestation → Verifier → VALID ✅
                                                      Tampered Packet  → Verifier → INVALID ❌
```

Data signed inside the TEE **cannot be fabricated by any software running on the same device**. This is a physics constraint, not an engineering preference.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              OMNIA-OS Device (Pixel 6/7)             │
│                                                      │
│  GPS Kernel Driver                                   │
│       │                                              │
│       ▼                                              │
│  Custom HAL (C/C++)  ←── reads BELOW Location API   │
│       │                                              │
│       ▼                                              │
│  TEE / StrongBox (Titan M2)                         │
│       │  ECDSA P-256 sign                            │
│       │  Private key NEVER leaves chip               │
│       ▼                                              │
│  Attestation Packet (JSON + Signature + Cert Chain) │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│           Attestation Verifier (Python)              │
│  1. Verify certificate chain → Google Root CA        │
│  2. Verify ECDSA P-256 signature                     │
│  3. Replay protection (30-second nonce window)       │
│  4. Return: VALID / INVALID + reason code            │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│         DirectHire™ Smart Contract (Polygon)         │
│  • Payment locked in EURC escrow                    │
│  • Proof-of-Delivery → auto-release                  │
│  • 5% protocol fee (vs 30% Glovo commission)         │
│  • Dispute → Decentralized Arbitration Module (DAM) │
└─────────────────────────────────────────────────────┘
```

---

## The Middleman Theory

iDARIA eliminates 8 classes of middlemen with one hardware root:

| Vertical | Middleman | Their Cut | iDARIA Fee | Year 3 ARR |
|---|---|---|---|---|
| V1 — DirectHire™ HR | Recruiter | 20–40% | 5% | $110M |
| V2 — Quick Commerce | Fraud teams | Crores/month | ₹3/delivery | $40M |
| V3 — TrustScore™ API | Fraud analysts | €120K/FTE/yr | €0.01/query | $30M |
| V4 — Expense Intel | Finance auditors | €45/claim | ~€0 | $12M |
| V5 — Behavioural Data | Google/Meta | 100% extracted | User earns tokens | $5M |
| V6 — OMNIA-SEARCH | Google Ads | $200B+/yr | TrustScore rank | Year 4+ |
| V7 — Rideshare Safety | Uber/Bolt layer | 25%/ride | $0.10/trip | $20M |
| V8 — Gig Liberation | Glovo/Deliveroo | 25–35% | 5% | $50M |

> **The rider's phone becomes the only middleman that matters. And unlike Glovo, it takes 0%.**

---

## The Five Tamper Tests

Our verification protocol defeats all standard attack vectors:

| Test | Attack Vector | Result | What It Proves |
|---|---|---|---|
| **T1** | Authentic TEE-signed packet | `VALID ✓` | Real hardware-signed data passes instantly |
| **T2** | Software GPS spoof (mock location app) | `CERT_CHAIN_INVALID ✗` | No TEE key = no valid cert chain |
| **T3** | Coordinate modified after signing | `SIGNATURE_INVALID ✗` | Any post-signing change detected |
| **T4** | Valid packet replayed 60 seconds later | `REPLAY_DETECTED ✗` | Nonce window prevents replay |
| **T5** | Signature transplanted from different packet | `SIGNATURE_INVALID ✗` | Signatures are payload-bound |

---

## Repository Structure

```
omnia-os-demo/
├── hal/
│   ├── omnia_hal.h              # C/C++ HAL interface definition
│   ├── omnia_hal.cpp            # GPS reading + TEE signing (stub)
│   ├── omnia_hal_gps.cpp        # [TODO Week 2] Real NDK GPS reading
│   ├── OmniaKeystore.java       # [TODO Week 3] StrongBox JNI bridge
│   └── Android.bp               # [TODO Week 3] AOSP Soong build config
├── verifier/
│   ├── verifier.py              # Flask attestation verifier (TESTED)
│   ├── test_suite.py            # T1–T5 automated tamper tests (TESTED)
│   └── requirements.txt         # Python dependencies
├── dashboard/
│   └── index.html               # Live demo UI (Leaflet + VALID/INVALID badge)
├── contracts/
│   └── DirectHireEscrow.sol     # Solidity escrow contract (Polygon)
├── ml/
│   └── trustscore_v1.py         # [TODO Month 2] TrustScore behavioral model
├── scripts/
│   ├── demo.sh                  # One-command demo runner
│   └── build_aosp.sh            # Reproducible AOSP build for Pixel 6
├── docs/
│   ├── TECHNICAL_SPEC.md        # Engineer-ready full specification
│   ├── ATTESTATION_FORMAT.md    # JSON schema and cert chain format
│   └── OUTREACH_MESSAGES.md     # Copy-paste contact templates
└── README.md
```

---

## Quick Start

### Run the verifier right now (no device needed)

```bash
git clone https://github.com/idaria-foundation/omnia-os-demo
cd omnia-os-demo/verifier
pip install -r requirements.txt
python verifier.py
# → Verifier running at http://localhost:5000

# In a second terminal:
python test_suite.py
# → All 5 tamper tests PASS in under 30 seconds
```

### Deploy the smart contract (Polygon Mumbai testnet)

```bash
# Open contracts/DirectHireEscrow.sol in Remix IDE
# remix.ethereum.org — completely free
# Deploy to Polygon Mumbai (get test MATIC from faucet.polygon.technology)
```

### Build the AOSP HAL (requires Android build environment)

```bash
source build/envsetup.sh
lunch aosp_oriole-userdebug   # Pixel 6
make omnia_hal -j$(nproc)
# Full setup guide: docs/TECHNICAL_SPEC.md Section 3
```

---

## Attestation Packet Format

```json
{
  "version": "1.0",
  "device_id": "<SHA256 of device certificate public key>",
  "reading": {
    "latitude": 45.0703,
    "longitude": 7.6869,
    "altitude": 239.0,
    "accuracy": 3.5,
    "timestamp_ns": 1741600000000000000,
    "nonce": "a3f9c2d1",
    "session_id": "abcdef1234567890abcdef1234567890"
  },
  "signature": "<base64-encoded ECDSA P-256 signature over canonical JSON of reading>",
  "cert_chain": [
    "<device leaf cert DER base64>",
    "<intermediate CA DER base64>",
    "<Google Hardware Attestation Root CA DER base64>"
  ]
}
```

---

## EU Regulatory Tailwinds

iDARIA satisfies four mandatory EU regulations — creating non-optional demand:

| Regulation | Deadline | iDARIA Compliance |
|---|---|---|
| eIDAS 2.0 (EU 2024/1183) | Dec 2026 | OMNIA-OS = hardware-anchored EUDI Wallet credential |
| EU Digital Product Passport (ESPR 2024/1781) | 2026–2030 | Hardware-signed GPS trace = automatic DPP supply chain provenance |
| EU AI Act (EU 2024/1689) | 2026 | TrustScore = only behavioral AI with hardware-verified data provenance |
| EU Platform Work Directive (2024) | Now | Hardware identity + on-chain disputes = full compliance |

---

## Current Status

- [x] Technical specification complete
- [x] Attestation packet format defined and documented
- [x] Python verifier — certificate chain + ECDSA + replay protection
- [x] T1–T5 automated tamper test suite — all tests passing
- [x] DirectHire escrow smart contract — Solidity on Polygon
- [x] Demo dashboard — browser-based with GPS map and test panel
- [ ] AOSP HAL — real Android NDK GPS integration (Week 2)
- [ ] Android Keystore / StrongBox JNI bridge (Week 3)
- [ ] TrustScore V1 ML model (Month 2)
- [ ] Turin pilot — 50 riders + 20 restaurants (Month 4)

---

## The Team

**Lokesh Nandre** — Founder & CEO | Turin, Italy
MSc Electronics for Robotics (Palermo) · AI Master (Rome Business School) · B.Sc Physics (NMU)

**Advisors:** Swapnil Kashyap (AI/ML, 24yr enterprise) · Abhishek Kumar Singh (Finance, BNY)

**Looking for:** Kernel engineer (AOSP/TEE/TrustZone) as technical co-founder. Equity-based. Turin or remote.

---

## Grant Applications

- **NGI Zero Commons Fund** — €50K — Submitted April 2026
- **Polygon Community Grants S2** — 500K POL — Submitted April 2026
- **Italy MISE Startup Innovativa** — €50K–200K — In progress
- **Horizon EIC Pathfinder** — up to €3M — Preparing

---

## License

Apache 2.0 — All code in this repository is open source. The iDARIA commercial ecosystem is built on top of this open-source foundation.

---

<div align="center">

*Built in Turin, Italy. Mathematics over middlemen.*

**lokesh@idaria.foundation · github.com/idaria-foundation**

</div>
