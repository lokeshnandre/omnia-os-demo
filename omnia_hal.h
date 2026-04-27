/*
 * OMNIA-OS Custom Hardware Abstraction Layer
 * iDARIA Foundation — Turin R&D Hub
 *
 * Interface definition for hardware-anchored sensor attestation.
 * Every data packet signed here is cryptographically bound to the
 * device's Trusted Execution Environment (TEE) private key.
 * The private key NEVER leaves the StrongBox/Titan M2 chip.
 *
 * Apache 2.0 License
 */

#ifndef OMNIA_HAL_H
#define OMNIA_HAL_H

#include <hardware/hardware.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Module Identity ───────────────────────────────────────────────────────── */

#define OMNIA_HAL_MODULE_ID    "omnia_attestation"
#define OMNIA_HAL_VERSION      HARDWARE_MODULE_API_VERSION(1, 0)

/* ── Data Structures ──────────────────────────────────────────────────────── */

/**
 * A single sensor reading captured at the kernel level.
 * All fields are populated BEFORE signing — none can be injected post-hoc.
 * Field order matches canonical JSON serialization (alphabetical by key).
 */
typedef struct omnia_sensor_reading {
    double   latitude;          /* WGS84 decimal degrees                      */
    double   longitude;         /* WGS84 decimal degrees                      */
    double   altitude;          /* meters above sea level                     */
    float    accuracy;          /* GPS accuracy estimate in meters             */
    int64_t  timestamp_ns;      /* monotonic clock, nanoseconds since epoch   */
    uint32_t nonce;             /* replay protection — increments per packet  */
    uint8_t  session_id[16];    /* random session UUID v4                     */
} omnia_sensor_reading_t;

/**
 * A complete attestation packet — the primary output of the HAL.
 * Contains: reading + TEE signature + certificate chain.
 * All three must be present and valid for the verifier to accept the packet.
 *
 * JSON format (verifier/verifier.py expects exactly this schema):
 * {
 *   "version": "1.0",
 *   "device_id": "<SHA256 hex of device cert public key>",
 *   "reading": { "accuracy":…, "altitude":…, "latitude":…, "longitude":…,
 *                "nonce":"…", "session_id":"…", "timestamp_ns":… },
 *   "signature": "<base64 ECDSA P-256 over canonical JSON of reading>",
 *   "cert_chain": ["<leaf DER b64>", "<intermediate b64>", "<Root CA b64>"]
 * }
 */
typedef struct omnia_attestation_packet {
    omnia_sensor_reading_t reading;

    /* ECDSA P-256 signature over canonical JSON of reading field */
    uint8_t  signature[256];
    size_t   signature_len;

    /* DER-encoded certificate chain:
     * [0] = device leaf cert (contains TEE-generated public key)
     * [1] = intermediate CA
     * [2] = Google Hardware Attestation Root CA
     */
    uint8_t  cert_chain[4096];
    size_t   cert_chain_len;

    /* Metadata */
    char     device_id[65];     /* SHA256 hex of device cert public key     */
    char     hal_version[16];   /* e.g., "1.0.0"                             */
} omnia_attestation_packet_t;

/* ── HAL Device Interface ─────────────────────────────────────────────────── */

typedef struct omnia_hal_device {
    struct hw_device_t common;

    /**
     * read_and_sign()
     *
     * Reads current GPS sensor data at the kernel level (below the
     * Android Location API, which can be spoofed by mock location apps)
     * and signs it inside the device's Trusted Execution Environment.
     *
     * The ECDSA P-256 private key is generated in StrongBox on first run
     * and hardware-bound — it NEVER leaves the Titan M2 chip.
     *
     * @param dev       Pointer to this device
     * @param out_packet Output: populated and signed attestation packet
     * @return          0 on success, negative errno on failure
     *
     * Error codes:
     *   -ENODEV    TEE/StrongBox not available
     *   -ETIMEDOUT GPS fix not available within timeout
     *   -EIO       TEE signing operation failed
     *   -EINVAL    Invalid output buffer
     */
    int (*read_and_sign)(
        struct omnia_hal_device* dev,
        omnia_attestation_packet_t* out_packet
    );

    /**
     * verify_local()
     *
     * Local (on-device) verification of a packet using the device's
     * own public key. For production use the remote verifier service
     * (verifier/verifier.py) which also verifies the certificate chain.
     *
     * @param packet    Packet to verify
     * @return          true if signature is valid and chain is intact
     */
    bool (*verify_local)(
        struct omnia_hal_device* dev,
        const omnia_attestation_packet_t* packet
    );

} omnia_hal_device_t;

/* ── Helper: Canonical JSON Serialisation ─────────────────────────────────── */

/**
 * Serialize a sensor reading to canonical JSON for signing.
 * Keys MUST be sorted alphabetically to match verifier expectations.
 *
 * Output example:
 * {"accuracy":3.500000,"altitude":239.000000,"latitude":45.0703000000,
 *  "longitude":7.6869000000,"nonce":"00000001",
 *  "session_id":"abcdef1234567890abcdef1234567890",
 *  "timestamp_ns":1741600000000000000}
 *
 * @param reading   Input reading struct
 * @param out_json  Output buffer for canonical JSON string
 * @param out_len   Size of output buffer (minimum 512 bytes)
 * @return          0 on success, -EINVAL/-EOVERFLOW on failure
 */
int omnia_serialize_reading(
    const omnia_sensor_reading_t* reading,
    char* out_json,
    size_t out_len
);

#ifdef __cplusplus
}
#endif

#endif /* OMNIA_HAL_H */
