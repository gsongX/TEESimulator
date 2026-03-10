## TEESimulator v4.2: Detection Evasion Hardening

Fixes 6 detection vectors flagged by attestation validator apps.

### Attestation Policy Enforcement

Replicate AOSP keystore2's `add_required_parameters()` validation that our software keygen path was bypassing:

- **CREATION_DATETIME** — Reject caller-provided input with `INVALID_ARGUMENT (20)`, matching `security_level.rs:424`. Our cert gen still adds its own timestamp, same as real keystore2.
- **Device ID attestation** — Reject ATTESTATION_ID_SERIAL, IMEI, MEID, SECOND_IMEI, and DEVICE_UNIQUE_ATTESTATION with `CANNOT_ATTEST_IDS (-66)`. No consumer app has READ_PRIVILEGED_PHONE_STATE.
- **Error reply format** — Fixed AIDL ServiceSpecificException parcel write order (was errorCode→message, now message→errorCode).

### Certificate Fix

Leaf certificate Subject CN corrected from "Android KeyStore Key" to "Android Keystore Key" (lowercase s), matching AOSP `KeyGenParameterSpec.java:282`. Both Kotlin and Rust paths.

### Binder Timing

Skip interception for system transaction codes (PING, INTERFACE, DUMP) above LAST_CALL_TRANSACTION. Eliminates the JNI round-trip that inflated binder ping ratio to 3.85x (detector threshold: 3.0x).

---

## TEESimulator v4.1: Boot Identity Persistence

Bugfix release. The vbmeta boot key digest was randomizing on every reboot, producing a different RootOfTrust in attestation certificates each boot.

On devices where the kernel doesn't set `ro.boot.vbmeta.public_key_digest`, the fallback chain hit random generation every boot because `resetprop` overrides for `ro.boot.*` props don't survive reboots. Added file-based persistence (`boot_hash.bin`, `boot_key.bin`) between the TEE cache and random fallback. Once determined, boot identity values persist across reboots.

Verified on Redmi 14C: second boot reads from persistent file instead of regenerating.

---

## TEESimulator v4.0: Native Rust Cert Generation

Major release. Certificate chain generation rebuilt from the ground up in Rust, replacing the BouncyCastle Java path for EC and RSA keys. Hardened against every known detector app.

### Native Cert Generation

The headline feature. `libcertgen.so` generates X.509 certificate chains using `ring` (EC-P256/P384) and `rsa` (RSA-2048/4096) with manual DER assembly. No more BouncyCastle quirks — issuer/subject DN bytes are injected directly from the keybox, ensuring byte-perfect chain linkage. BouncyCastle remains as fallback for unsupported curves (P-224, P-521, Curve25519).

### Anti-Detection Hardening

- **Challenge validation** — Oversized attestation challenges (>128 bytes) now return `INVALID_INPUT_LENGTH (-21)`, matching real KeyMint behavior. Previously accepted silently — DuckDetector exploited this.
- **Per-UID rate limiter** — 2 hardware keygens per 30s burst, 2 concurrent max. Overflow falls back to software certs. Blocks DuckDetector-style keygen flooding that starves GMS.
- **importKey eviction guard** — Retained patch chains prevent generate-then-import attacks that evict cached attestation data.
- **256KB native payload cap** — Oversized binder payloads bypass interception cleanly instead of stalling threads.
- **Alias size rejection** — Oversized key aliases rejected before they hit the binder buffer.

### Key Persistence

Generated keys now survive reboots. File-backed storage with file-level locking, preserved across keybox rotations. Banking and biometric apps that cache attestation keys no longer break after restart.

### Attestation Fixes

- Null out all-zero `verifiedBootHash` from TEE cache (fingerprinting vector)
- Correct `module_hash` field to match AOSP Keystore2 format
- Override pre-existing attest keys instead of skipping them
- Strip HTML comments from PEM blocks in keybox parsing
- Security patch consistency — `system=prop` forces boot/vendor to match

### Module Lifecycle

- Supervisor daemon keeps the interceptor alive
- KSU Action button clears persistent key cache
- Clean uninstall removes all traces (persistent keys, TEE status, daemon)

### Stability

- FileObserver NPE on config deletion fixed
- Global uncaught exception handler — daemon stays alive on unexpected errors
- PEM parsing hardened against malformed keybox files

### Tested Against

DuckDetector, Luna, Play Integrity, Key Attestation Demo — all passing on Redmi 14C (Android 14, Beanpod KeyMaster, KSU).

---

## 🚀 Release: TEESimulator v3.2 (Hotfix)

TEESimulator v3.2 is rolling out today as an hotfix. This release was pushed ahead of schedule because our recent GitHub build artifacts were expiring, and a severe Google Play Services (GMS) log flooding bug was significantly degrading device performance for many users. 📱⚡

⚠️ **Important Development Update:**
*   **Detections:** Due to time constraints, we haven't patched *all* the new detections currently in the wild. However, this hotfix does successfully address a few critical detection points. 🛡️
*   **LSPosed ➡️ Vector:** I (JingMatrix) am currently dedicating my efforts to refactoring LSPosed into **Vector**. Consequently, TEESimulator's development pace will temporarily slow down. Please stay tuned and monitor the commit history to follow along with our progress! 🛠️👀

Here is the changelog for this release:

🔧 **Stability & Performance**
*   **🛑 GMS Log Flooding:** Mitigated massive log spam and battery drain (especially noticeable on WearOS or Nearby Share) by safely bypassing `list` hooks for GMS.
*   **💥 Binder Leak Resolved:** Squashed a critical strong reference memory leak during binder transaction interception that caused random crashes.

🛡️ **Anti-Detection & Emulation**
*   **🔑 Pre-Existing Key Override:** TEESimulator now detects and replaces hardware keys that apps managed to request *before* the module was installed, ensuring all future operations remain under control.
*   **🧩 Accurate `module_hash`:** Completely aligned the APEX module hashing logic with the official Android `keystore2` implementation (including direct `/apex` filesystem scanning and exact ASN.1 DER sorting).
*   **📜 Certificate `KeyUsage` Fix:** Dynamically sets X.509 `KeyUsage` bits based on the actual key purpose to properly adhere to Android HAL specifications *(the first contribution of @Enginex0!)*.
*   **⚙️ Core Improvements:** Enhanced KeyMint logging (parsing `ORIGIN`, `OS_VERSION`, etc.) and fixed Parcel position resets for cleaner internal error handling.
