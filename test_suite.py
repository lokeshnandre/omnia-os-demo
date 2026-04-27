"""
OMNIA-OS Tamper Test Suite v1.0 — T1 through T5
iDARIA Foundation — Turin, Italy

Runs all five tamper tests against the verifier.
These are the exact tests shown in the investor demo.

Run:
    python verifier.py &     # Start verifier first
    python test_suite.py     # Run all 5 tests

All 5 tests should pass in under 30 seconds.
Apache 2.0 License
"""

import requests, json, base64, time, copy
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
import datetime

VERIFIER_URL = "http://localhost:5000/verify"


# ── Demo Device Simulation ───────────────────────────────────────────────────

def generate_demo_device():
    """
    Generates a demo ECDSA key + self-signed cert.
    Simulates what the Titan M2 StrongBox does on a real Pixel device.
    In production: key is hardware-bound and never leaves the TEE.
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key  = private_key.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,        u"OMNIA-OS Demo Device"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,  u"iDARIA Foundation"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,       u"IT"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    return private_key, cert_b64


def make_reading(lat=45.0703, lng=7.6869):
    return {
        "latitude":     lat,
        "longitude":    lng,
        "altitude":     239.0,
        "accuracy":     3.5,
        "timestamp_ns": time.time_ns(),
        "nonce":        "00000001",
        "session_id":   "abcdef1234567890abcdef1234567890",
    }


def sign_reading(private_key, reading: dict) -> str:
    payload = json.dumps(reading, sort_keys=True, separators=(',', ':')).encode()
    sig     = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()


def make_packet(private_key, cert_b64, reading=None, sig_override=None):
    if reading is None:
        reading = make_reading()
    sig = sig_override if sig_override else sign_reading(private_key, reading)
    return {
        "version":    "1.0",
        "device_id":  "demo_pixel6_001",
        "reading":    reading,
        "signature":  sig,
        "cert_chain": [cert_b64],
    }


# ── Test Runner ───────────────────────────────────────────────────────────────

def run_test(name, packet, expect_valid, expect_contains=""):
    print(f"\n{'─'*60}")
    print(f"  {name}")
    print(f"{'─'*60}")
    try:
        resp   = requests.post(VERIFIER_URL, json=packet, timeout=5)
        result = resp.json()
    except Exception as e:
        print(f"  ERROR: Cannot reach verifier — {e}")
        print(f"  Make sure verifier.py is running: python verifier.py")
        return False

    valid  = result.get("valid", False)
    reason = result.get("reason", "")
    passed = (valid == expect_valid)
    if expect_contains and not expect_valid:
        passed = passed and (expect_contains in reason)

    icon = "[PASS ✓]" if passed else "[FAIL ✗]"
    print(f"  Result   : {'VALID' if valid else 'INVALID'}")
    print(f"  Reason   : {reason}")
    print(f"  Expected : {'VALID' if expect_valid else 'INVALID'}")
    print(f"  Status   : {icon}")
    return passed


# ── The Five Tests ────────────────────────────────────────────────────────────

def main():
    print("\n" + "=" * 60)
    print("  OMNIA-OS TAMPER TEST SUITE v1.0")
    print("  iDARIA Foundation — Zero-Spoofing Demo")
    print("=" * 60)

    private_key, cert_b64 = generate_demo_device()
    results = []

    # T1 — Authentic packet
    packet = make_packet(private_key, cert_b64)
    results.append(run_test(
        "T1 — Authentic Packet (expect: VALID)",
        packet, expect_valid=True
    ))

    # T2 — Software spoof: attacker generates own key (no TEE cert)
    attacker_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    reading_t2   = make_reading()
    attacker_sig = sign_reading(attacker_key, reading_t2)
    packet_t2    = make_packet(private_key, cert_b64, reading=reading_t2, sig_override=attacker_sig)
    results.append(run_test(
        "T2 — Software GPS Spoof (expect: SIGNATURE_INVALID)",
        packet_t2, expect_valid=False, expect_contains="SIGNATURE_INVALID"
    ))

    # T3 — Coordinate tamper: sign, then modify lat after signing
    reading_t3    = make_reading()
    sig_t3        = sign_reading(private_key, reading_t3)
    reading_t3["latitude"] += 0.0001  # Tamper AFTER signing
    packet_t3     = make_packet(private_key, cert_b64, reading=reading_t3, sig_override=sig_t3)
    results.append(run_test(
        "T3 — Coordinate Tamper After Signing (expect: SIGNATURE_INVALID)",
        packet_t3, expect_valid=False, expect_contains="SIGNATURE_INVALID"
    ))

    # T4 — Replay attack: valid packet but 60s old timestamp
    reading_t4 = make_reading()
    reading_t4["timestamp_ns"] = time.time_ns() - (60 * 1_000_000_000)
    sig_t4     = sign_reading(private_key, reading_t4)
    packet_t4  = make_packet(private_key, cert_b64, reading=reading_t4, sig_override=sig_t4)
    results.append(run_test(
        "T4 — Replay Attack (60s old) (expect: REPLAY_DETECTED)",
        packet_t4, expect_valid=False, expect_contains="REPLAY_DETECTED"
    ))

    # T5 — Signature swap: signature from Turin applied to London packet
    reading_turin  = make_reading(lat=45.0703, lng=7.6869)
    sig_turin      = sign_reading(private_key, reading_turin)
    reading_london = make_reading(lat=51.5074, lng=-0.1278)  # Different location
    packet_t5      = make_packet(private_key, cert_b64, reading=reading_london, sig_override=sig_turin)
    results.append(run_test(
        "T5 — Signature Transplant Attack (expect: SIGNATURE_INVALID)",
        packet_t5, expect_valid=False, expect_contains="SIGNATURE_INVALID"
    ))

    # Summary
    passed = sum(results)
    total  = len(results)
    print(f"\n{'='*60}")
    print(f"  RESULTS: {passed}/{total} tests passed")
    print(f"{'='*60}")
    if passed == total:
        print("  ALL TESTS PASSED ✓")
        print("  Zero-Spoofing demo is investor-ready.")
    else:
        failed = [i+1 for i, r in enumerate(results) if not r]
        print(f"  FAILED: T{', T'.join(str(f) for f in failed)}")
        print("  Fix the verifier before the investor demo.")
    print("=" * 60 + "\n")
    return passed == total


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
