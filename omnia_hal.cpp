/*
 * OMNIA-OS Custom HAL — Implementation Stub
 * iDARIA Foundation — Turin R&D Hub
 *
 * Phase 0 implementation. GPS reading is stubbed (returns Turin coordinates).
 * TEE signing calls are bridged via JNI to OmniaKeystore.java (TODO Week 3).
 *
 * PRODUCTION TODO:
 *   Week 2: Replace GPS stub with real NDK Location API (omnia_hal_gps.cpp)
 *   Week 3: Implement OmniaKeystore.java JNI bridge for real StrongBox signing
 *   Week 4: Test T1-T5 suite on real Pixel 6 device
 *
 * Apache 2.0 License
 */

#define LOG_TAG "OmniaHAL"

#include "omnia_hal.h"
#include <utils/Log.h>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <errno.h>

/* ── Forward Declarations (JNI bridge to OmniaKeystore.java) ─────────────── */
/* TODO Week 3: implement these in OmniaKeystore.java                          */
extern "C" {
    int omnia_tee_generate_key(const char* alias);
    int omnia_tee_sign(const char* alias,
                       const uint8_t* data, size_t data_len,
                       uint8_t* sig_out, size_t* sig_len_out);
    int omnia_tee_get_cert_chain(const char* alias,
                                  uint8_t* cert_out, size_t* cert_len_out);
}

/* ── Constants ───────────────────────────────────────────────────────────── */
static const char* OMNIA_KEY_ALIAS = "omnia_device_key_v1";
static uint32_t    g_nonce = 0;

/* ── Canonical JSON Serialisation ────────────────────────────────────────── */

int omnia_serialize_reading(const omnia_sensor_reading_t* r,
                             char* out, size_t out_len)
{
    if (!r || !out || out_len < 512) return -EINVAL;

    /* Keys MUST be sorted alphabetically to match Python verifier */
    int n = snprintf(out, out_len,
        "{"
        "\"accuracy\":%.6f,"
        "\"altitude\":%.6f,"
        "\"latitude\":%.10f,"
        "\"longitude\":%.10f,"
        "\"nonce\":\"%08x\","
        "\"session_id\":\"%02x%02x%02x%02x%02x%02x%02x%02x"
                          "%02x%02x%02x%02x%02x%02x%02x%02x\","
        "\"timestamp_ns\":%lld"
        "}",
        r->accuracy, r->altitude, r->latitude, r->longitude, r->nonce,
        r->session_id[0],  r->session_id[1],  r->session_id[2],  r->session_id[3],
        r->session_id[4],  r->session_id[5],  r->session_id[6],  r->session_id[7],
        r->session_id[8],  r->session_id[9],  r->session_id[10], r->session_id[11],
        r->session_id[12], r->session_id[13], r->session_id[14], r->session_id[15],
        (long long)r->timestamp_ns
    );
    return (n > 0 && (size_t)n < out_len) ? 0 : -EOVERFLOW;
}

/* ── GPS Reading (STUB — replace in Week 2) ──────────────────────────────── */

static int read_gps_kernel(omnia_sensor_reading_t* r) {
    /*
     * TODO Week 2: Replace with real kernel GPS driver read.
     *
     * Production path:
     *   1. Open GnssHal interface or read /dev/gnss directly
     *   2. Parse NMEA at kernel level — below Android Location API
     *   3. GPS spoof apps operate above the Location API, so kernel
     *      reading is unaffected by any user-space mock location.
     *
     * Phase 0 STUB: Turin coordinates for development.
     * The TEE signing still works — the spoofing protection comes
     * from the hardware key, not just the GPS reading path.
     */
    r->latitude    = 45.0703;
    r->longitude   = 7.6869;
    r->altitude    = 239.0;
    r->accuracy    = 3.5f;
    r->timestamp_ns = (int64_t)time(nullptr) * 1000000000LL;
    r->nonce       = ++g_nonce;

    memset(r->session_id, 0, sizeof(r->session_id));
    memcpy(r->session_id, &g_nonce, sizeof(g_nonce));

    ALOGD("OmniaHAL: GPS stub — lat=%.6f lon=%.6f nonce=%u",
          r->latitude, r->longitude, r->nonce);
    return 0;
}

/* ── HAL Device Methods ───────────────────────────────────────────────────── */

static int omnia_read_and_sign(omnia_hal_device_t* dev,
                                omnia_attestation_packet_t* out)
{
    (void)dev;
    if (!out) return -EINVAL;
    memset(out, 0, sizeof(*out));

    /* Step 1: Read GPS */
    int ret = read_gps_kernel(&out->reading);
    if (ret) { ALOGE("OmniaHAL: GPS read failed: %d", ret); return ret; }

    /* Step 2: Serialize to canonical JSON */
    char json[512];
    ret = omnia_serialize_reading(&out->reading, json, sizeof(json));
    if (ret) { ALOGE("OmniaHAL: Serialize failed: %d", ret); return ret; }
    ALOGD("OmniaHAL: Signing payload: %s", json);

    /* Step 3: Sign inside TEE (StrongBox) via JNI bridge */
    out->signature_len = sizeof(out->signature);
    ret = omnia_tee_sign(OMNIA_KEY_ALIAS,
                          (const uint8_t*)json, strlen(json),
                          out->signature, &out->signature_len);
    if (ret) { ALOGE("OmniaHAL: TEE sign failed: %d", ret); return ret; }

    /* Step 4: Get certificate chain from KeyStore */
    out->cert_chain_len = sizeof(out->cert_chain);
    ret = omnia_tee_get_cert_chain(OMNIA_KEY_ALIAS,
                                    out->cert_chain, &out->cert_chain_len);
    if (ret) { ALOGE("OmniaHAL: Cert chain failed: %d", ret); return ret; }

    /* Step 5: Fill metadata */
    snprintf(out->device_id, sizeof(out->device_id), "omnia_%08x", g_nonce);
    snprintf(out->hal_version, sizeof(out->hal_version), "1.0.0");

    ALOGI("OmniaHAL: Packet ready — sig_len=%zu cert_len=%zu",
          out->signature_len, out->cert_chain_len);
    return 0;
}

static bool omnia_verify_local(omnia_hal_device_t* dev,
                                 const omnia_attestation_packet_t* packet)
{
    (void)dev; (void)packet;
    /* TODO Week 4: implement local verify using stored public key */
    ALOGW("OmniaHAL: Local verify not yet implemented — use verifier.py");
    return false;
}

/* ── Module Open / Close ──────────────────────────────────────────────────── */

static int omnia_close(hw_device_t* device) {
    free(device);
    return 0;
}

static int omnia_open(const hw_module_t* module, const char* id,
                       hw_device_t** device)
{
    if (strcmp(id, OMNIA_HAL_MODULE_ID) != 0) return -EINVAL;

    omnia_hal_device_t* dev = (omnia_hal_device_t*)calloc(1, sizeof(*dev));
    if (!dev) return -ENOMEM;

    dev->common.tag     = HARDWARE_DEVICE_TAG;
    dev->common.version = OMNIA_HAL_VERSION;
    dev->common.module  = (hw_module_t*)module;
    dev->common.close   = omnia_close;
    dev->read_and_sign  = omnia_read_and_sign;
    dev->verify_local   = omnia_verify_local;

    /* Ensure TEE key exists */
    int ret = omnia_tee_generate_key(OMNIA_KEY_ALIAS);
    if (ret) {
        ALOGE("OmniaHAL: TEE key init failed: %d", ret);
        free(dev);
        return ret;
    }

    *device = &dev->common;
    ALOGI("OmniaHAL: Device opened. Turin pilot ready.");
    return 0;
}

/* ── Module Registration ──────────────────────────────────────────────────── */

static hw_module_methods_t omnia_methods = { .open = omnia_open };

hw_module_t HAL_MODULE_INFO_SYM = {
    .tag                = HARDWARE_MODULE_TAG,
    .module_api_version = OMNIA_HAL_VERSION,
    .hal_api_version    = HARDWARE_HAL_API_VERSION,
    .id                 = OMNIA_HAL_MODULE_ID,
    .name               = "OMNIA-OS Attestation HAL",
    .author             = "iDARIA Foundation",
    .methods            = &omnia_methods,
};
