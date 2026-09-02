#ifndef CRYPT_H_
#define CRYPT_H_

#include <stddef.h>
#include <stdint.h>
#include <psa/crypto.h>

/*
 * ChaCha20-Poly1305 AEAD via mbedtls's PSA crypto API. Ported from the
 * machdyne/blaustahl feature/encryption branch. Deliberately returns
 * status codes only -- no printf/logging of any kind, since this
 * firmware's printf shares a wire with the live VT100 UI (the same
 * lesson learned the hard way with littlefs's default logging macros
 * earlier in this project). Callers (storage.c) decide what, if
 * anything, gets shown to the user.
 */

int crypt_init(psa_key_id_t *key, const uint8_t *key_bytes);

// hands a key slot back and clears the caller's handle. mbedtls 2.28
// has a fixed table of 32 volatile key slots and frees one only on an
// explicit psa_destroy_key(), so EVERY crypt_init() needs a matching
// release -- on the failure paths just as much as the success ones.
// Verifying a password imports a key and then decrypts to check the
// AEAD tag, so without this a wrong guess burns a slot: the 33rd
// import fails with PSA_ERROR_INSUFFICIENT_MEMORY and the correct
// passphrase reports "INCORRECT PASSWORD." until a power cycle. Safe
// on an already-zero handle.
void crypt_key_release(psa_key_id_t *key);

// generic SHA-256, used by storage.c to mix multiple inputs (RNG
// output, the board's unique ID, a timestamp) into a well-diffused
// salt rather than relying on get_rand_32() alone. See the discussion
// in the project notes: pico_rand's xoroshiro128** core is a fast
// statistical PRNG, not a cryptographic one, and its entropy sources
// are explicitly documented as "of varying quality" -- mixing in the
// board's factory-unique ID guarantees no cross-device salt collision
// regardless of RNG quality, independent of whatever pico_rand itself
// turns out to provide.
int crypt_hash(const uint8_t *data, size_t len, uint8_t *out32);

// derives a 32-byte key from SHA256(password || salt). password is
// treated as a C string, up to 32 characters, zero-padded to exactly
// 32 bytes before hashing (so "hi" and "hi" followed by 30 NUL bytes
// hash identically -- this matches the reference implementation's
// fixed-width password field, just derived from a real string instead
// of requiring the caller to pre-pad a 32-byte buffer themselves).
// key_out must have room for 32 bytes.
//
// LEGACY (LTSF algo 1) -- kept only so existing encrypted FRAM can
// still be unlocked and then upgraded. A single unsalted-speed SHA-256
// is far too fast a KDF for password-derived keys: anyone who dumps
// the ciphertext (SRWP hands it out raw, no password needed) can
// brute-force offline at GPU hash rates. New formats use
// crypt_kdf_pbkdf2() below. Do not use this for anything new.
int crypt_kdf(const char *password, const uint8_t *salt, uint8_t *key_out);

// derives a 32-byte key with PBKDF2-HMAC-SHA256 (LTSF algo 2). The
// full password string participates (no 32-char truncation). `iters`
// is stored in LTSF metadata so it can be tuned per-device/per-era
// without a format break. ~100k iterations runs in roughly a second
// on the RP2040 at 120MHz -- imperceptible at unlock time, but five
// orders of magnitude more work per guess for an offline attacker
// than the legacy single hash. Returns 1 on success, 0 on failure.
int crypt_kdf_pbkdf2(const char *password, const uint8_t *salt,
	uint32_t iters, uint8_t *key_out);

int crypt_encrypt(psa_key_id_t key, const uint8_t *nonce, const uint8_t *aad,
	const uint8_t *pt, size_t pt_size,
	uint8_t *ct, size_t ct_size, size_t *ct_len);

int crypt_decrypt(psa_key_id_t key, const uint8_t *nonce, const uint8_t *aad,
	const uint8_t *ct, size_t ct_size,
	uint8_t *pt, size_t pt_size, size_t *pt_len);

void crypt_nonce_inc(uint8_t *nonce);

#endif
