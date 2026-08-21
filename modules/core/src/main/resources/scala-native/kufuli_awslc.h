/*
 * Copyright (c) 2026 Ali Rashid.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef KUFULI_AWSLC_H
#define KUFULI_AWSLC_H

#include <stddef.h>
#include <stdint.h>

/* Every function returns 1 for success and 0 for failure, without exception. aws-lc itself does not:
 * AES_set_encrypt_key returns 0 on success, AES_wrap_key returns a length or -1, ECDH_compute_key
 * returns a length or -1, and the SHA/HMAC one-shots return a pointer. Normalising here means the
 * Scala side cannot misread a convention. Out-lengths are written only on success.
 *
 * Every out-buffer parameter is accompanied by the caller's capacity and that capacity is checked
 * BEFORE the first byte is written. Where an entry point takes an out buffer with no capacity, the
 * length is fixed by the algorithm named in the same call (a digest, a 32-byte X25519 secret) and
 * is stated in that function's contract. */

#ifdef __cplusplus
extern "C" {
#endif

/* Algorithm selectors. Values are kufuli's own and are matched in kufuli.awslc; they exist so the
 * binding passes an int rather than resolving a `const EVP_AEAD *` across the FFI. */
#define KUFULI_AEAD_AES_128_GCM 1
#define KUFULI_AEAD_AES_192_GCM 2
#define KUFULI_AEAD_AES_256_GCM 3
#define KUFULI_AEAD_CHACHA20_POLY1305 4
#define KUFULI_AEAD_XCHACHA20_POLY1305 5
#define KUFULI_AEAD_AES_256_GCM_SIV 6

#define KUFULI_MD_SHA1 1
#define KUFULI_MD_SHA256 2
#define KUFULI_MD_SHA384 3
#define KUFULI_MD_SHA512 4

#define KUFULI_KEM_ML_KEM_768 1
#define KUFULI_KEM_ML_KEM_1024 2

/* Asymmetric key types (an EVP_PKEY handle's family). */
#define KUFULI_PKEY_ED25519 1
#define KUFULI_PKEY_X25519 2
#define KUFULI_PKEY_P256 3
#define KUFULI_PKEY_P384 4
#define KUFULI_PKEY_P521 5
#define KUFULI_PKEY_RSA 6

/* Signature schemes. */
#define KUFULI_SCHEME_ED25519 1
#define KUFULI_SCHEME_ECDSA 2
#define KUFULI_SCHEME_RSA_PSS 3
#define KUFULI_SCHEME_RSA_PKCS1 4

/* Identity of the linked library: 1 iff this shim was compiled and linked against aws-lc. Calls
 * awslc_api_version_num, which no other OpenSSL-compatible library exports. The compile-time
 * OPENSSL_IS_AWSLC assertion and the link-time dialect gate both hold at BUILD time; this is the
 * only check that sees a consumer who rebound the library to a system shared object, so the Scala
 * binding asserts it once before handing out any instance. */
int kufuli_is_awslc(void);

/* CSPRNG. Cannot fail: aws-lc's RAND_bytes aborts rather than return an error. */
int kufuli_random_bytes(uint8_t *out, size_t len);

/* AEAD. The context is an opaque heap EVP_AEAD_CTX; one per Cipher lifetime. Every algorithm above
 * is on aead.h's documented concurrency allow-list, so seal/open may be called concurrently on one
 * context. kufuli_aead_free zeroises before releasing. */
void *kufuli_aead_new(int alg, const uint8_t *key, size_t key_len);
void kufuli_aead_free(void *ctx);
int kufuli_aead_seal(const void *ctx, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *in, size_t in_len, const uint8_t *ad, size_t ad_len);
int kufuli_aead_open(const void *ctx, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *in, size_t in_len, const uint8_t *ad, size_t ad_len);

/* HKDF (RFC 5869). aws-lc's HKDF_extract takes the secret BEFORE the salt, reversing RFC 5869's
 * HKDF-Extract(salt, IKM); both are (const uint8_t *, size_t), so a transposition there compiles
 * and silently derives wrong keys. These wrappers fix the RFC's order at the boundary. */
int kufuli_hkdf_extract(uint8_t *out_prk, size_t *out_len, int md, const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                        size_t ikm_len);
int kufuli_hkdf_expand(uint8_t *out, size_t out_len, int md, const uint8_t *prk, size_t prk_len, const uint8_t *info,
                       size_t info_len);

/* PBKDF2-HMAC (RFC 8018). */
int kufuli_pbkdf2(uint8_t *out, size_t out_len, int md, const uint8_t *password, size_t password_len, const uint8_t *salt,
                  size_t salt_len, uint32_t iterations);

/* HMAC one-shot. */
int kufuli_hmac(int md, const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out, size_t *out_len);

/* Digests. `out` receives exactly the digest length of `md`. */
int kufuli_digest(int md, const uint8_t *data, size_t len, uint8_t *out);

/* Incremental hashing. kufuli_hasher_digest SNAPSHOTS: it copies the context and finalises the copy,
 * leaving the original updatable (the TLS transcript shape). */
void *kufuli_hasher_new(int md);
void kufuli_hasher_free(void *ctx);
int kufuli_hasher_update(void *ctx, const uint8_t *data, size_t len);
int kufuli_hasher_digest(const void *ctx, uint8_t *out);

/* AES-KW (RFC 3394) and AES-KWP (RFC 5649), over the default IV. AES_wrap_key writes before it can
 * report a length, so the plain variants check max_out against the RFC's fixed +/-8 relation first;
 * the padded variants take max_out themselves. */
int kufuli_aes_wrap(uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *kek, size_t kek_len, const uint8_t *in,
                    size_t in_len, int padded);
int kufuli_aes_unwrap(uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *kek, size_t kek_len, const uint8_t *in,
                      size_t in_len, int padded);

/* AES-CBC with PKCS#7 padding (128/256 by key length), the block cipher under the RFC 7518
 * AES-CBC-HMAC-SHA2 composite; the MAC layout and constant-time tag check live in shared Scala. */
int kufuli_aes_cbc(int encrypt, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *key, size_t key_len,
                   const uint8_t *iv, const uint8_t *in, size_t in_len);

/* Raw AES-ECB single block and ChaCha20 keystream: the kufuli.unsafe floor (QUIC header protection). */
int kufuli_aes_block_encrypt(uint8_t *out, const uint8_t *in, const uint8_t *key, size_t key_len);
int kufuli_chacha20_keystream(uint8_t *out, size_t out_len, const uint8_t *key, const uint8_t *nonce, uint32_t counter);

/* ML-KEM (FIPS 203). The parameter set fixes every length; each entry point queries aws-lc for the
 * true size and refuses before writing when the caller's capacity is smaller.
 * kufuli_kem_public_valid runs the section 7.2 encapsulation-key check at import, so a malformed
 * peer key is a value rather than a failure deep inside encapsulation.
 * kufuli_kem_keypair_from_seed is FIPS 203 KeyGen over the 64-byte (d || z) seed. */
int kufuli_kem_public_valid(int kem, const uint8_t *pub, size_t pub_len);
int kufuli_kem_keypair(int kem, uint8_t *out_pub, size_t *out_pub_len, size_t max_pub, uint8_t *out_priv,
                       size_t *out_priv_len, size_t max_priv);
int kufuli_kem_keypair_from_seed(int kem, const uint8_t *seed, size_t seed_len, uint8_t *out_pub, size_t *out_pub_len,
                                 size_t max_pub, uint8_t *out_priv, size_t *out_priv_len, size_t max_priv);
int kufuli_kem_encapsulate(int kem, const uint8_t *pub, size_t pub_len, uint8_t *out_ct, size_t *out_ct_len, size_t max_ct,
                           uint8_t *out_ss, size_t *out_ss_len, size_t max_ss);
int kufuli_kem_decapsulate(int kem, const uint8_t *priv, size_t priv_len, const uint8_t *ct, size_t ct_len, uint8_t *out_ss,
                           size_t *out_ss_len, size_t max_ss);

/* Asymmetric keys and operations over an opaque EVP_PKEY handle. The Scala side owns the handle
 * lifecycle: it parses a key once (per op, or once per prepared Signer/Agreement resource), operates,
 * then frees. Keys are stored by kufuli as SPKI (public) / PKCS#8 (private) DER, except ML-KEM which
 * travels raw. Every parse validates: a bad encoding, an off-curve point or a wrong length yields a
 * NULL handle, which the Scala side maps to a typed InvalidKey. */
void *kufuli_pkey_generate(int type, int rsa_bits);
void kufuli_pkey_free(void *pkey);

void *kufuli_pkey_from_spki(const uint8_t *der, size_t len);
void *kufuli_pkey_from_pkcs8(const uint8_t *der, size_t len);
void *kufuli_pkey_from_raw_public(int type, const uint8_t *raw, size_t len);
void *kufuli_pkey_from_ec_point(int type, const uint8_t *point, size_t len);
void *kufuli_pkey_from_rsa_components(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len);

/* These two return -1, with the encoding's true length in *out_len, when `max_out` is too small,
 * so a large key is re-marshalled at its own size instead of failing; 1 on success, 0 on failure. */
int kufuli_pkey_spki(const void *pkey, uint8_t *out, size_t *out_len, size_t max_out);
int kufuli_pkey_pkcs8(const void *pkey, uint8_t *out, size_t *out_len, size_t max_out);
int kufuli_pkey_raw_public(const void *pkey, uint8_t *out, size_t *out_len, size_t max_out);
int kufuli_pkey_ec_point(const void *pkey, uint8_t *out, size_t *out_len, size_t max_out);
int kufuli_pkey_rsa_components(const void *pkey, uint8_t *n_out, size_t *n_len, size_t n_max, uint8_t *e_out, size_t *e_len,
                              size_t e_max);

/* EC signing produces the DER `SEQUENCE { r, s }`; the fixed-width r||s conversion is kufuli's shared
 * codec above the shim, matching every backend. `md` is ignored for Ed25519 (which is one-shot). */
int kufuli_pkey_sign(const void *pkey, int scheme, int md, const uint8_t *data, size_t len, uint8_t *out, size_t *out_len,
                     size_t max_out);
int kufuli_pkey_verify(const void *pkey, int scheme, int md, const uint8_t *data, size_t len, const uint8_t *sig,
                       size_t sig_len);
int kufuli_pkey_derive(const void *priv, const void *peer_pub, uint8_t *out, size_t *out_len, size_t max_out);
int kufuli_pkey_oaep_encrypt(const void *pub, int md, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len,
                             size_t max_out);
int kufuli_pkey_oaep_decrypt(const void *priv, int md, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len,
                             size_t max_out);

#ifdef __cplusplus
}
#endif

#endif /* KUFULI_AWSLC_H */
