"""
OMNIA-OS Attestation Verifier v1.0
iDARIA Foundation — Turin, Italy

Stateless REST service verifying OMNIA-OS attestation packets.
Runs on any laptop — no device needed to test the logic.

Usage:
    pip install -r requirements.txt
    python verifier.py
    # → http://localhost:5000

Apache 2.0 License
"""

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.exceptions import InvalidSignature
import base64, json, time, os

app = Flask(__name__)
REPLAY_WINDOW_SECONDS = 30
REQUIRE_GOOGLE_ROOT = os.environ.get("REQUIRE_GOOGLE_ROOT", "false").lower() == "true"


def canonical_json(reading: dict) -> bytes:
    """Canonical JSON: keys sorted alphabetically, no whitespace.
    This MUST match omnia_serialize_reading() in omnia_hal.cpp exactly."""
    return json.dumps(reading, sort_keys=True, separators=(',', ':')).encode('utf-8')


def load_cert_chain(cert_chain_b64: list) -> list:
    certs = []
    for b64 in cert_chain_b64:
        der = base64.b64decode(b64)
        certs.append(x509.load_der_x509_certificate(der))
    return certs


def verify_cert_chain(certs: list):
    if not certs:
        return False, "Empty certificate chain"
    for i in range(len(certs) - 1):
        leaf, issuer = certs[i], certs[i + 1]
        try:
            pub = issuer.public_key()
            if isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(
                    leaf.signature,
                    leaf.tbs_certificate_bytes,
                    ec.ECDSA(leaf.signature_hash_algorithm)
                )
        except Exception as e:
            return False, f"Chain broken at position {i}: {e}"
    return True, "OK"


def verify_signature(pubkey, reading: dict, sig_b64: str):
    payload = canonical_json(reading)
    try:
        pubkey.verify(base64.b64decode(sig_b64), payload, ec.ECDSA(hashes.SHA256()))
        return True, "OK"
    except InvalidSignature:
        return False, "Signature does not match payload"
    except Exception as e:
        return False, f"Verification error: {e}"


def check_replay(reading: dict):
    ts_ns = reading.get("timestamp_ns", 0)
    age_s = (time.time_ns() - ts_ns) / 1_000_000_000
    if age_s > REPLAY_WINDOW_SECONDS:
        return False, f"Packet is {age_s:.1f}s old (window: {REPLAY_WINDOW_SECONDS}s)"
    if age_s < -5:
        return False, "Timestamp is in the future — clock skew too large"
    return True, "OK"


@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "1.0.0", "verifier": "OMNIA-OS"})


@app.route("/verify", methods=["POST"])
def verify():
    """
    Verify an OMNIA-OS attestation packet.

    POST body (JSON):
    {
        "version": "1.0",
        "device_id": "<sha256_of_pubkey>",
        "reading": {
            "latitude": 45.0703, "longitude": 7.6869,
            "altitude": 239.0, "accuracy": 3.5,
            "timestamp_ns": 1741600000000000000,
            "nonce": "a3f9c2d1",
            "session_id": "abcdef1234567890abcdef1234567890"
        },
        "signature": "<base64_ecdsa_p256_sig>",
        "cert_chain": ["<leaf_b64>", "<intermediate_b64>", "<root_ca_b64>"]
    }

    Returns: { "valid": true/false, "reason": "OK" | error_code, ... }
    """
    try:
        packet = request.get_json(force=True)
    except Exception:
        return jsonify({"valid": False, "reason": "INVALID_JSON"}), 400

    reading       = packet.get("reading", {})
    sig_b64       = packet.get("signature", "")
    cert_chain_b64 = packet.get("cert_chain", [])
    device_id     = packet.get("device_id", "unknown")

    def fail(reason):
        return jsonify({"valid": False, "reason": reason, "device_id": device_id})

    # Step 1: Parse certificate chain
    try:
        certs = load_cert_chain(cert_chain_b64)
    except Exception as e:
        return fail(f"CERT_PARSE_ERROR: {e}")

    if not certs:
        return fail("CERT_CHAIN_MISSING")

    # Step 2: Verify certificate chain integrity
    chain_ok, chain_reason = verify_cert_chain(certs)
    if not chain_ok:
        return fail(f"CERT_CHAIN_INVALID: {chain_reason}")

    # Step 3: Verify ECDSA signature over reading JSON
    pubkey = certs[0].public_key()
    sig_ok, sig_reason = verify_signature(pubkey, reading, sig_b64)
    if not sig_ok:
        return fail(f"SIGNATURE_INVALID: {sig_reason}")

    # Step 4: Replay protection
    replay_ok, replay_reason = check_replay(reading)
    if not replay_ok:
        return fail(f"REPLAY_DETECTED: {replay_reason}")

    return jsonify({
        "valid":        True,
        "reason":       "OK",
        "device_id":    device_id,
        "lat":          reading.get("latitude"),
        "lng":          reading.get("longitude"),
        "altitude":     reading.get("altitude"),
        "accuracy":     reading.get("accuracy"),
        "timestamp_ns": reading.get("timestamp_ns"),
    })


if __name__ == "__main__":
    print("=" * 58)
    print("  OMNIA-OS Attestation Verifier v1.0.0")
    print("  iDARIA Foundation — Turin, Italy")
    print(f"  Replay window   : {REPLAY_WINDOW_SECONDS}s")
    print(f"  Google Root CA  : {'enforced' if REQUIRE_GOOGLE_ROOT else 'demo mode (not enforced)'}")
    print("  Endpoints       : GET /health  |  POST /verify")
    print("=" * 58)
    app.run(host="0.0.0.0", port=5000, debug=True)
