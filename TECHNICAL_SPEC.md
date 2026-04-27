# OMNIA-OS Technical Specification v1.0
**iDARIA Foundation — Turin R&D Hub**

---

## 1. System Overview

OMNIA-OS is a custom AOSP fork with a hardware-anchored attestation pipeline. It reads sensor data at the kernel level, signs it inside the device's Trusted Execution Environment (TEE), and produces cryptographically verifiable attestation packets that are impossible to fabricate in software.

```
GPS Kernel Driver (below Android Location API)
        │
        ▼
Custom C/C++ HAL (omnia_hal.cpp)
        │  reads sensor data
        ▼
Canonical JSON Serializer
        │  {"accuracy":…, "altitude":…, "latitude":…, …}
        ▼
TEE / StrongBox (Titan M2)
        │  ECDSA P-256 sign — private key NEVER leaves chip
        ▼
Attestation Packet (JSON + Signature + Cert Chain)
        │
        ▼
Remote Verifier (verifier/verifier.py)
        │  1. Verify cert chain → Google Hardware Attestation Root CA
        │  2. Verify ECDSA P-256 signature over reading JSON
        │  3. Replay protection (30-second nonce window)
        ▼
VALID ✅ / INVALID ❌ + reason code
        │
        ▼ (if VALID)
DirectHire™ Smart Contract (Polygon)
        │  EURC escrow auto-release
        ▼
Worker receives payment (95% of escrow)
iDARIA receives fee (5% of escrow)
```

---

## 2. Attestation Packet Format

### 2.1 JSON Schema

```json
{
  "version": "1.0",
  "device_id": "<SHA256 hex of device certificate public key>",
  "reading": {
    "accuracy":     3.5,
    "altitude":     239.0,
    "latitude":     45.0703000000,
    "longitude":    7.6869000000,
    "nonce":        "a3f9c2d1",
    "session_id":   "abcdef1234567890abcdef1234567890",
    "timestamp_ns": 1741600000000000000
  },
  "signature": "<base64url ECDSA P-256 signature over canonical JSON of reading>",
  "cert_chain": [
    "<device leaf certificate DER base64>",
    "<intermediate CA DER base64>",
    "<Google Hardware Attestation Root CA DER base64>"
  ]
}
```

### 2.2 Canonical JSON Rules

The `reading` object MUST be serialized with:
- Keys sorted **alphabetically** (accuracy, altitude, latitude, longitude, nonce, session_id, timestamp_ns)
- No whitespace between tokens
- Numbers serialized to **6 decimal places** for floats, **exact integer** for timestamp_ns
- nonce as 8-character hex string (zero-padded)
- session_id as 32-character hex string

**Python reference implementation:**
```python
json.dumps(reading, sort_keys=True, separators=(',', ':'))
```

**C++ reference implementation:**
```cpp
snprintf(buf, len,
  "{\"accuracy\":%.6f,\"altitude\":%.6f,\"latitude\":%.10f,"
  "\"longitude\":%.10f,\"nonce\":\"%08x\",\"session_id\":\"%s\","
  "\"timestamp_ns\":%lld}",
  r.accuracy, r.altitude, r.latitude, r.longitude,
  r.nonce, hex_session_id, r.timestamp_ns);
```

---

## 3. Hardware Layer

### 3.1 AOSP Build Setup (Pixel 6)

```bash
# Ubuntu 22.04 LTS recommended
sudo apt-get install -y git-core gnupg flex bison build-essential \
    zip curl zlib1g-dev libc6-dev-i386 libncurses5 \
    x11proto-core-dev libx11-dev libgl1-mesa-dev \
    libxml2-utils xsltproc unzip fontconfig python3 python-is-python3

# Install repo tool
mkdir -p ~/.bin
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/.bin/repo
chmod a+x ~/.bin/repo
export PATH="${HOME}/.bin:${PATH}"

# Clone AOSP (Pixel 6 = Android 13, tag android-13.0.0_r82)
mkdir ~/aosp && cd ~/aosp
repo init -u https://android.googlesource.com/platform/manifest \
          -b android-13.0.0_r82
repo sync -j$(nproc) --no-tags

# Set up build environment
source build/envsetup.sh
lunch aosp_oriole-userdebug   # oriole = Pixel 6

# Build (first build: 2-4 hours)
make -j$(nproc)
```

### 3.2 Device Setup (Pixel 6)

```bash
# Enable Developer Options: Settings → About Phone → tap Build Number 7x
# Enable USB Debugging and OEM Unlocking

# Unlock bootloader
adb reboot bootloader
fastboot flashing unlock

# Flash AOSP
fastboot flashall -w

# Verify device boots and HAL is present
adb shell getprop ro.product.device  # should be "oriole"
adb logcat | grep OmniaHAL
```

### 3.3 TEE Requirements

OMNIA-OS requires **StrongBox** support (hardware security module separate from the main TEE). Supported devices:
- Pixel 4 and later (Titan M chip family)
- Samsung Galaxy S20 and later (with Titan M or equivalent)

To verify StrongBox availability:
```kotlin
val km = getSystemService(KeyguardManager::class.java)
val strongBox = packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
```

### 3.4 Key Generation (OmniaKeystore.java — TODO Week 3)

```java
// TODO: implement this in hal/OmniaKeystore.java
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
);
keyPairGenerator.initialize(
    new KeyGenParameterSpec.Builder(
        "omnia_device_key_v1",
        KeyProperties.PURPOSE_SIGN
    )
    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setIsStrongBoxBacked(true)        // <-- hardware-bound
    .setAttestationChallenge(nonce)    // <-- for certificate chain
    .build()
);
KeyPair keyPair = keyPairGenerator.generateKeyPair();
```

---

## 4. Verifier Service

### 4.1 API Endpoints

**GET /health**
```json
{ "status": "ok", "version": "1.0.0", "verifier": "OMNIA-OS" }
```

**POST /verify**

Request: attestation packet JSON (see Section 2.1)

Response (success):
```json
{
  "valid": true,
  "reason": "OK",
  "device_id": "...",
  "lat": 45.0703,
  "lng": 7.6869,
  "timestamp_ns": 1741600000000000000
}
```

Response (failure):
```json
{
  "valid": false,
  "reason": "SIGNATURE_INVALID: Signature does not match payload",
  "device_id": "..."
}
```

### 4.2 Reason Codes

| Code | Meaning |
|---|---|
| `OK` | Valid — payment can proceed |
| `CERT_CHAIN_INVALID` | Certificate chain broken or invalid (T2) |
| `CERT_CHAIN_MISSING` | No certificate chain in packet |
| `SIGNATURE_INVALID` | ECDSA signature verification failed (T3, T5) |
| `REPLAY_DETECTED` | Packet timestamp outside 30-second window (T4) |
| `CERT_PARSE_ERROR` | Malformed certificate DER |
| `INVALID_JSON` | Malformed request body |

### 4.3 Replay Protection

- Verifier maintains a 30-second acceptance window
- `timestamp_ns` must be within `[now - 30s, now + 5s]`
- Production V2: maintain a nonce registry to prevent reuse within window

---

## 5. Smart Contract

### 5.1 DirectHire Escrow Flow

```
Client creates contract → funds EURC escrow
Worker accepts → starts working
Worker submits OMNIA-OS attestation hash → contract verifies
All milestones complete → auto-release payment
Worker receives 95%, iDARIA receives 5%
```

### 5.2 Deployment (Polygon Mumbai Testnet)

```
1. Open https://remix.ethereum.org
2. Paste contracts/DirectHireEscrow.sol
3. Compile with Solidity 0.8.20
4. Connect MetaMask to Polygon Mumbai
5. Deploy with IDARIA_PLATFORM = your test wallet address
6. Get test MATIC: faucet.polygon.technology
```

### 5.3 Polygon Mainnet (Post-Audit)

Requires:
- Slither or Mythril static analysis
- Professional audit (budget: €15,000-20,000)
- Multi-sig for IDARIA_PLATFORM address

---

## 6. TrustScore Model (TODO Month 2)

### 6.1 Feature Engineering from TEE-Signed Data

```python
features = {
    "delivery_count":         len(signed_packets),
    "avg_accuracy_m":         mean([p.accuracy for p in packets]),
    "speed_variance":         variance([gps_speed(p) for p in packets]),
    "route_entropy":          route_entropy(packets),
    "stop_pattern_regularity": stop_regularity(packets),
    "time_consistency":       time_of_day_variance(packets),
    "nonce_continuity":       nonce_gap_analysis(packets),
}
```

### 6.2 Score Interpretation

| Score | Interpretation | Example |
|---|---|---|
| 950-1000 | Excellent | 2,000+ verified deliveries, consistent routes |
| 850-950  | Good       | 500+ verified, minor anomalies |
| 700-850  | Fair       | Limited history or some variance |
| <700     | Low        | New account or behavioral anomalies |

---

## 7. Build Roadmap

| Week | Task | Owner | Status |
|---|---|---|---|
| 1 | AOSP build env. Pixel 6 flashed. | Founder | TODO |
| 2 | `omnia_hal_gps.cpp` — real NDK GPS | Founder | TODO |
| 3 | `OmniaKeystore.java` — StrongBox JNI | Co-Founder | TODO |
| 3 | `Android.bp` — AOSP Soong build | Co-Founder | TODO |
| 4 | T1-T5 pass on real device | Both | TODO |
| M2 | `ml/trustscore_v1.py` — TrustScore model | AI Advisor | TODO |
| M2 | `contracts/TrustScoreOracle.sol` | Solidity Lead | TODO |
| M3 | `api/server.py` — iDARIA Trust API | Founder | TODO |
| M4 | Turin pilot: 50 riders, 20 restaurants | All | TODO |

---

*iDARIA Foundation — Turin, Italy — lokesh@idaria.foundation*
