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
#include "kufuli_awslc.h"

#include <openssl/base.h>

/* aws-lc ships is_awslc.h expressly to catch include-path errors, and base.h defines
 * OPENSSL_IS_AWSLC. Asserting it turns an -I resolved onto stock OpenSSL headers into a directed
 * failure here, rather than a cascade of undefined dialect symbols at link. */
#ifndef OPENSSL_IS_AWSLC
#error "kufuli requires aws-lc: the OpenSSL include path did not resolve to aws-lc headers"
#endif

#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/chacha.h>
#include <openssl/cipher.h>
#include <openssl/crypto.h>
#include <openssl/curve25519.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <string.h>

static const EVP_AEAD *aead_of(int alg) {
  switch (alg) {
    case KUFULI_AEAD_AES_128_GCM: return EVP_aead_aes_128_gcm();
    case KUFULI_AEAD_AES_192_GCM: return EVP_aead_aes_192_gcm();
    case KUFULI_AEAD_AES_256_GCM: return EVP_aead_aes_256_gcm();
    case KUFULI_AEAD_CHACHA20_POLY1305: return EVP_aead_chacha20_poly1305();
    case KUFULI_AEAD_XCHACHA20_POLY1305: return EVP_aead_xchacha20_poly1305();
    case KUFULI_AEAD_AES_256_GCM_SIV: return EVP_aead_aes_256_gcm_siv();
    default: return NULL;
  }
}

static const EVP_MD *md_of(int md) {
  switch (md) {
    case KUFULI_MD_SHA1: return EVP_sha1();
    case KUFULI_MD_SHA256: return EVP_sha256();
    case KUFULI_MD_SHA384: return EVP_sha384();
    case KUFULI_MD_SHA512: return EVP_sha512();
    default: return NULL;
  }
}

static int kem_nid_of(int kem) {
  switch (kem) {
    case KUFULI_KEM_ML_KEM_768: return NID_MLKEM768;
    case KUFULI_KEM_ML_KEM_1024: return NID_MLKEM1024;
    default: return NID_undef;
  }
}

int kufuli_is_awslc(void) { return awslc_api_version_num() > 0 ? 1 : 0; }

int kufuli_random_bytes(uint8_t *out, size_t len) {
  if (len == 0) return 1;
  return RAND_bytes(out, len);
}

int kufuli_ct_equals(const uint8_t *a, const uint8_t *b, size_t len) {
  if (len == 0) return 1;
  return CRYPTO_memcmp(a, b, len) == 0 ? 1 : 0;
}

void kufuli_cleanse(uint8_t *p, size_t len) {
  if (len > 0) OPENSSL_cleanse(p, len);
}

void *kufuli_aead_new(int alg, const uint8_t *key, size_t key_len) {
  const EVP_AEAD *aead = aead_of(alg);
  if (aead == NULL) return NULL;
  /* EVP_AEAD_DEFAULT_TAG_LENGTH: the AEAD's own tag length, which is what every algorithm we ship
   * uses. A context is const on seal/open and each of these AEADs is on aead.h's concurrency
   * allow-list, so one context serves a Cipher's whole lifetime. */
  return EVP_AEAD_CTX_new(aead, key, key_len, EVP_AEAD_DEFAULT_TAG_LENGTH);
}

void kufuli_aead_free(void *ctx) {
  if (ctx != NULL) EVP_AEAD_CTX_free((EVP_AEAD_CTX *)ctx);
}

int kufuli_aead_seal(const void *ctx, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *in, size_t in_len, const uint8_t *ad, size_t ad_len) {
  if (ctx == NULL) return 0;
  return EVP_AEAD_CTX_seal((const EVP_AEAD_CTX *)ctx, out, out_len, max_out, nonce, nonce_len, in, in_len, ad, ad_len);
}

int kufuli_aead_open(const void *ctx, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *in, size_t in_len, const uint8_t *ad, size_t ad_len) {
  if (ctx == NULL) return 0;
  return EVP_AEAD_CTX_open((const EVP_AEAD_CTX *)ctx, out, out_len, max_out, nonce, nonce_len, in, in_len, ad, ad_len);
}

/* Argument order is the RFC's (salt, ikm); HKDF_extract's is (secret, salt). The swap is the whole
 * point of this wrapper. */
int kufuli_hkdf_extract(uint8_t *out_prk, size_t *out_len, int md, const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                        size_t ikm_len) {
  const EVP_MD *digest = md_of(md);
  if (digest == NULL) return 0;
  return HKDF_extract(out_prk, out_len, digest, ikm, ikm_len, salt, salt_len);
}

int kufuli_hkdf_expand(uint8_t *out, size_t out_len, int md, const uint8_t *prk, size_t prk_len, const uint8_t *info,
                       size_t info_len) {
  const EVP_MD *digest = md_of(md);
  if (digest == NULL) return 0;
  return HKDF_expand(out, out_len, digest, prk, prk_len, info, info_len);
}

int kufuli_pbkdf2(uint8_t *out, size_t out_len, int md, const uint8_t *password, size_t password_len, const uint8_t *salt,
                  size_t salt_len, uint32_t iterations) {
  const EVP_MD *digest = md_of(md);
  if (digest == NULL) return 0;
  return PKCS5_PBKDF2_HMAC((const char *)password, (size_t)password_len, salt, salt_len, (unsigned)iterations, digest, out_len,
                           out);
}

int kufuli_hmac(int md, const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out,
                size_t *out_len) {
  const EVP_MD *digest = md_of(md);
  unsigned int n = 0;
  if (digest == NULL) return 0;
  /* HMAC returns |out| or NULL, not an int. */
  if (HMAC(digest, key, key_len, data, data_len, out, &n) == NULL) return 0;
  *out_len = (size_t)n;
  return 1;
}

int kufuli_digest_size(int md) {
  const EVP_MD *digest = md_of(md);
  return digest == NULL ? 0 : (int)EVP_MD_size(digest);
}

int kufuli_digest(int md, const uint8_t *data, size_t len, uint8_t *out) {
  const EVP_MD *digest = md_of(md);
  unsigned int n = 0;
  if (digest == NULL) return 0;
  return EVP_Digest(data, len, out, &n, digest, NULL);
}

void *kufuli_hasher_new(int md) {
  const EVP_MD *digest = md_of(md);
  EVP_MD_CTX *ctx = NULL;
  if (digest == NULL) return NULL;
  ctx = EVP_MD_CTX_new();
  if (ctx == NULL) return NULL;
  if (!EVP_DigestInit_ex(ctx, digest, NULL)) {
    EVP_MD_CTX_free(ctx);
    return NULL;
  }
  return ctx;
}

void kufuli_hasher_free(void *ctx) {
  if (ctx != NULL) EVP_MD_CTX_free((EVP_MD_CTX *)ctx);
}

int kufuli_hasher_update(void *ctx, const uint8_t *data, size_t len) {
  if (ctx == NULL) return 0;
  if (len == 0) return 1;
  return EVP_DigestUpdate((EVP_MD_CTX *)ctx, data, len);
}

/* Snapshot: finalising consumes a context, so copy first and finalise the copy. EVP_MD_CTX_copy_ex
 * requires an already-initialised destination (unlike the deprecated EVP_MD_CTX_copy). */
int kufuli_hasher_digest(const void *ctx, uint8_t *out) {
  EVP_MD_CTX *snapshot = NULL;
  unsigned int n = 0;
  int ok = 0;
  if (ctx == NULL) return 0;
  snapshot = EVP_MD_CTX_new();
  if (snapshot == NULL) return 0;
  if (EVP_MD_CTX_copy_ex(snapshot, (const EVP_MD_CTX *)ctx)) ok = EVP_DigestFinal_ex(snapshot, out, &n);
  EVP_MD_CTX_free(snapshot);
  return ok;
}

int kufuli_ed25519_keypair(uint8_t *out_pub, uint8_t *out_priv) {
  ED25519_keypair(out_pub, out_priv); /* void */
  return 1;
}

int kufuli_ed25519_from_seed(uint8_t *out_pub, uint8_t *out_priv, const uint8_t *seed) {
  ED25519_keypair_from_seed(out_pub, out_priv, seed); /* void */
  return 1;
}

int kufuli_ed25519_sign(uint8_t *out_sig, const uint8_t *msg, size_t msg_len, const uint8_t *priv) {
  return ED25519_sign(out_sig, msg, msg_len, priv);
}

int kufuli_ed25519_verify(const uint8_t *msg, size_t msg_len, const uint8_t *sig, const uint8_t *pub) {
  return ED25519_verify(msg, msg_len, sig, pub);
}

int kufuli_x25519_keypair(uint8_t *out_pub, uint8_t *out_priv) {
  X25519_keypair(out_pub, out_priv); /* void */
  return 1;
}

int kufuli_x25519_public_from_private(uint8_t *out_pub, const uint8_t *priv) {
  X25519_public_from_private(out_pub, priv); /* void */
  return 1;
}

int kufuli_x25519(uint8_t *out_shared, const uint8_t *priv, const uint8_t *peer_pub) {
  return X25519(out_shared, priv, peer_pub);
}

int kufuli_aes_wrap(uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *kek, size_t kek_len, const uint8_t *in,
                    size_t in_len, int padded) {
  AES_KEY key;
  /* AES_set_encrypt_key returns ZERO on success - the header warns it breaks the convention. */
  if (AES_set_encrypt_key(kek, (unsigned)(kek_len * 8), &key) != 0) return 0;
  if (padded) return AES_wrap_key_padded(&key, out, out_len, max_out, in, in_len);
  /* AES_wrap_key returns the written length or -1, not 1/0. NULL iv selects the RFC 3394 default. */
  {
    int n = AES_wrap_key(&key, NULL, out, in, in_len);
    if (n < 0 || (size_t)n > max_out) return 0;
    *out_len = (size_t)n;
    return 1;
  }
}

int kufuli_aes_unwrap(uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *kek, size_t kek_len, const uint8_t *in,
                      size_t in_len, int padded) {
  AES_KEY key;
  if (AES_set_decrypt_key(kek, (unsigned)(kek_len * 8), &key) != 0) return 0;
  if (padded) return AES_unwrap_key_padded(&key, out, out_len, max_out, in, in_len);
  {
    int n = AES_unwrap_key(&key, NULL, out, in, in_len);
    if (n < 0 || (size_t)n > max_out) return 0;
    *out_len = (size_t)n;
    return 1;
  }
}

int kufuli_aes_cbc(int encrypt, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *key, size_t key_len,
                   const uint8_t *iv, const uint8_t *in, size_t in_len) {
  const EVP_CIPHER *cipher = key_len == 16 ? EVP_aes_128_cbc() : key_len == 32 ? EVP_aes_256_cbc() : NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  int len1 = 0;
  int len2 = 0;
  int ok = 0;
  (void)max_out; /* the caller sizes out at in_len + one block; PKCS#7 padding never exceeds that */
  if (cipher == NULL) return 0;
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) return 0;
  if (encrypt) {
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) && EVP_EncryptUpdate(ctx, out, &len1, in, (int)in_len) &&
        EVP_EncryptFinal_ex(ctx, out + len1, &len2)) {
      *out_len = (size_t)(len1 + len2);
      ok = 1;
    }
  } else {
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) && EVP_DecryptUpdate(ctx, out, &len1, in, (int)in_len) &&
        EVP_DecryptFinal_ex(ctx, out + len1, &len2)) {
      *out_len = (size_t)(len1 + len2);
      ok = 1;
    }
  }
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

int kufuli_aes_block_encrypt(uint8_t *out, const uint8_t *in, const uint8_t *key, size_t key_len) {
  AES_KEY k;
  if (AES_set_encrypt_key(key, (unsigned)(key_len * 8), &k) != 0) return 0;
  AES_encrypt(in, out, &k); /* void, exactly one 16-byte block */
  OPENSSL_cleanse(&k, sizeof(k));
  return 1;
}

/* Keystream = ChaCha20 over zeros: aws-lc exposes CRYPTO_chacha_20 as an XOR, so encrypting a zero
 * buffer yields the raw keystream. QUIC header protection needs the first five bytes. */
int kufuli_chacha20_keystream(uint8_t *out, size_t out_len, const uint8_t *key, const uint8_t *nonce, uint32_t counter) {
  if (out_len == 0) return 1;
  memset(out, 0, out_len);
  CRYPTO_chacha_20(out, out, out_len, key, nonce, counter);
  return 1;
}

/* ML-KEM. Sizes come from the EVP size-check convention (both output buffers NULL -> lengths only),
 * so they are read from the library rather than hardcoded from an uninstalled internal header. */
int kufuli_kem_sizes(int kem, size_t *out_pub, size_t *out_priv, size_t *out_ct, size_t *out_ss) {
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *key = NULL;
  EVP_PKEY_CTX *ectx = NULL;
  int nid = kem_nid_of(kem);
  int ok = 0;
  if (nid == NID_undef) return 0;
  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, NULL);
  if (ctx == NULL) return 0;
  if (EVP_PKEY_CTX_kem_set_params(ctx, nid) && EVP_PKEY_keygen_init(ctx) && EVP_PKEY_keygen(ctx, &key)) {
    size_t pub_len = 0, priv_len = 0;
    if (EVP_PKEY_get_raw_public_key(key, NULL, &pub_len) && EVP_PKEY_get_raw_private_key(key, NULL, &priv_len)) {
      ectx = EVP_PKEY_CTX_new(key, NULL);
      /* Both output buffers NULL is the documented size-check call. */
      if (ectx != NULL && EVP_PKEY_encapsulate(ectx, NULL, out_ct, NULL, out_ss)) {
        *out_pub = pub_len;
        *out_priv = priv_len;
        ok = 1;
      }
    }
  }
  EVP_PKEY_CTX_free(ectx);
  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(ctx);
  return ok;
}

int kufuli_kem_keypair(int kem, uint8_t *out_pub, size_t *out_pub_len, uint8_t *out_priv, size_t *out_priv_len) {
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *key = NULL;
  int nid = kem_nid_of(kem);
  int ok = 0;
  if (nid == NID_undef) return 0;
  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, NULL);
  if (ctx == NULL) return 0;
  if (EVP_PKEY_CTX_kem_set_params(ctx, nid) && EVP_PKEY_keygen_init(ctx) && EVP_PKEY_keygen(ctx, &key)) {
    /* get_raw_*_key takes the buffer capacity in *out_len on entry; a size query fills it from the
     * key so the caller need only pass a buffer sized to the parameter set (as the others do). */
    size_t pub_len = 0;
    size_t priv_len = 0;
    if (EVP_PKEY_get_raw_public_key(key, NULL, &pub_len) && EVP_PKEY_get_raw_private_key(key, NULL, &priv_len)) {
      *out_pub_len = pub_len;
      *out_priv_len = priv_len;
      ok = EVP_PKEY_get_raw_public_key(key, out_pub, out_pub_len) && EVP_PKEY_get_raw_private_key(key, out_priv, out_priv_len);
    }
  }
  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(ctx);
  return ok;
}

int kufuli_kem_encapsulate(int kem, const uint8_t *pub, size_t pub_len, uint8_t *out_ct, size_t *out_ct_len, uint8_t *out_ss,
                           size_t *out_ss_len) {
  EVP_PKEY *key = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  int nid = kem_nid_of(kem);
  int ok = 0;
  if (nid == NID_undef) return 0;
  key = EVP_PKEY_kem_new_raw_public_key(nid, pub, pub_len);
  if (key == NULL) return 0;
  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (ctx != NULL) {
    /* EVP_PKEY_encapsulate checks the ciphertext and shared-secret buffer capacities on entry; the
     * NULL-buffer size query fills them from the KEM. */
    size_t ct_len = 0;
    size_t ss_len = 0;
    if (EVP_PKEY_encapsulate(ctx, NULL, &ct_len, NULL, &ss_len)) {
      *out_ct_len = ct_len;
      *out_ss_len = ss_len;
      ok = EVP_PKEY_encapsulate(ctx, out_ct, out_ct_len, out_ss, out_ss_len);
    }
  }
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(key);
  return ok;
}

/* Total by construction: FIPS 203 implicit rejection returns a pseudorandom secret for a forged
 * ciphertext rather than an error, which is what makes kufuli's decapsulate total. */
int kufuli_kem_decapsulate(int kem, const uint8_t *priv, size_t priv_len, const uint8_t *ct, size_t ct_len, uint8_t *out_ss,
                           size_t *out_ss_len) {
  EVP_PKEY *key = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  int nid = kem_nid_of(kem);
  int ok = 0;
  if (nid == NID_undef) return 0;
  key = EVP_PKEY_kem_new_raw_secret_key(nid, priv, priv_len);
  if (key == NULL) return 0;
  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (ctx != NULL) {
    size_t ss_len = 0;
    if (EVP_PKEY_decapsulate(ctx, NULL, &ss_len, ct, ct_len)) {
      *out_ss_len = ss_len;
      ok = EVP_PKEY_decapsulate(ctx, out_ss, out_ss_len, ct, ct_len);
    }
  }
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(key);
  return ok;
}

static int ec_curve_nid(int type) {
  switch (type) {
    case KUFULI_PKEY_P256: return NID_X9_62_prime256v1;
    case KUFULI_PKEY_P384: return NID_secp384r1;
    case KUFULI_PKEY_P521: return NID_secp521r1;
    default: return NID_undef;
  }
}

/* Copies a CBB-marshalled key into the caller's buffer. CBB_finish hands back an OPENSSL_free'd
 * buffer; on any failure CBB_cleanup releases the partial state. */
static int marshal_into(int (*fn)(CBB *, const EVP_PKEY *), const EVP_PKEY *pkey, uint8_t *out, size_t *out_len,
                        size_t max_out) {
  CBB cbb;
  uint8_t *data = NULL;
  size_t len = 0;
  int ok = 0;
  CBB_zero(&cbb);
  if (CBB_init(&cbb, 0) && fn(&cbb, pkey) && CBB_finish(&cbb, &data, &len)) {
    if (len <= max_out) {
      memcpy(out, data, len);
      *out_len = len;
      ok = 1;
    }
    OPENSSL_free(data);
  } else {
    CBB_cleanup(&cbb);
  }
  return ok;
}

void *kufuli_pkey_generate(int type, int rsa_bits) {
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *key = NULL;
  switch (type) {
    case KUFULI_PKEY_ED25519: ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL); break;
    case KUFULI_PKEY_X25519: ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL); break;
    case KUFULI_PKEY_P256:
    case KUFULI_PKEY_P384:
    case KUFULI_PKEY_P521: ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL); break;
    case KUFULI_PKEY_RSA: ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); break;
    default: return NULL;
  }
  if (ctx == NULL) return NULL;
  if (EVP_PKEY_keygen_init(ctx)) {
    int cfg = 1;
    if (type == KUFULI_PKEY_P256 || type == KUFULI_PKEY_P384 || type == KUFULI_PKEY_P521)
      cfg = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, ec_curve_nid(type));
    else if (type == KUFULI_PKEY_RSA)
      cfg = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, rsa_bits);
    if (cfg) {
      if (!EVP_PKEY_keygen(ctx, &key)) key = NULL;
    }
  }
  EVP_PKEY_CTX_free(ctx);
  return key;
}

void kufuli_pkey_free(void *pkey) {
  if (pkey != NULL) EVP_PKEY_free((EVP_PKEY *)pkey);
}

int kufuli_pkey_type(const void *pkey) {
  switch (EVP_PKEY_id((const EVP_PKEY *)pkey)) {
    case EVP_PKEY_ED25519: return KUFULI_PKEY_ED25519;
    case EVP_PKEY_X25519: return KUFULI_PKEY_X25519;
    case EVP_PKEY_RSA: return KUFULI_PKEY_RSA;
    case EVP_PKEY_EC: return KUFULI_PKEY_P256;
    default: return 0;
  }
}

void *kufuli_pkey_from_spki(const uint8_t *der, size_t len) {
  CBS cbs;
  EVP_PKEY *key = NULL;
  CBS_init(&cbs, der, len);
  key = EVP_parse_public_key(&cbs);
  if (key != NULL && CBS_len(&cbs) != 0) { /* trailing bytes are malformed */
    EVP_PKEY_free(key);
    return NULL;
  }
  return key;
}

void *kufuli_pkey_from_pkcs8(const uint8_t *der, size_t len) {
  CBS cbs;
  EVP_PKEY *key = NULL;
  CBS_init(&cbs, der, len);
  key = EVP_parse_private_key(&cbs);
  if (key != NULL && CBS_len(&cbs) != 0) {
    EVP_PKEY_free(key);
    return NULL;
  }
  return key;
}

void *kufuli_pkey_from_raw_public(int type, const uint8_t *raw, size_t len) {
  int evp = type == KUFULI_PKEY_ED25519 ? EVP_PKEY_ED25519 : type == KUFULI_PKEY_X25519 ? EVP_PKEY_X25519 : NID_undef;
  if (evp == NID_undef) return NULL;
  return EVP_PKEY_new_raw_public_key(evp, NULL, raw, len);
}

/* EC_POINT_oct2point validates the point is on the curve, so an off-curve SEC1 encoding yields a
 * NULL handle (a typed NotOnCurve above the shim). */
void *kufuli_pkey_from_ec_point(int type, const uint8_t *point, size_t len) {
  int nid = ec_curve_nid(type);
  EC_KEY *ec = NULL;
  EC_POINT *pt = NULL;
  EVP_PKEY *key = NULL;
  const EC_GROUP *group = NULL;
  if (nid == NID_undef) return NULL;
  ec = EC_KEY_new_by_curve_name(nid);
  if (ec == NULL) return NULL;
  group = EC_KEY_get0_group(ec);
  pt = EC_POINT_new(group);
  if (pt != NULL && EC_POINT_oct2point(group, pt, point, len, NULL) && EC_KEY_set_public_key(ec, pt)) {
    key = EVP_PKEY_new();
    if (key != NULL && EVP_PKEY_assign_EC_KEY(key, ec)) {
      ec = NULL; /* ownership transferred */
    } else {
      EVP_PKEY_free(key);
      key = NULL;
    }
  }
  EC_POINT_free(pt);
  EC_KEY_free(ec); /* frees unless ownership transferred */
  return key;
}

void *kufuli_pkey_from_rsa_components(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len) {
  BIGNUM *bn_n = BN_bin2bn(n, n_len, NULL);
  BIGNUM *bn_e = BN_bin2bn(e, e_len, NULL);
  RSA *rsa = NULL;
  EVP_PKEY *key = NULL;
  if (bn_n != NULL && bn_e != NULL) {
    rsa = RSA_new_public_key(bn_n, bn_e); /* copies the BIGNUMs */
    if (rsa != NULL) {
      key = EVP_PKEY_new();
      if (key != NULL && EVP_PKEY_assign_RSA(key, rsa)) {
        rsa = NULL;
      } else {
        EVP_PKEY_free(key);
        key = NULL;
      }
    }
  }
  BN_free(bn_n);
  BN_free(bn_e);
  RSA_free(rsa);
  return key;
}

int kufuli_pkey_spki(const void *pkey, uint8_t *out, size_t *out_len, size_t max_out) {
  return marshal_into(EVP_marshal_public_key, (const EVP_PKEY *)pkey, out, out_len, max_out);
}

int kufuli_pkey_pkcs8(const void *pkey, uint8_t *out, size_t *out_len, size_t max_out) {
  return marshal_into(EVP_marshal_private_key, (const EVP_PKEY *)pkey, out, out_len, max_out);
}

int kufuli_pkey_raw_public(const void *pkey, uint8_t *out, size_t *out_len, size_t max_out) {
  size_t len = max_out;
  if (!EVP_PKEY_get_raw_public_key((const EVP_PKEY *)pkey, out, &len)) return 0;
  *out_len = len;
  return 1;
}

int kufuli_pkey_ec_point(const void *pkey, uint8_t *out, size_t *out_len, size_t max_out) {
  EC_KEY *ec = EVP_PKEY_get1_EC_KEY((EVP_PKEY *)pkey);
  size_t n = 0;
  if (ec == NULL) return 0;
  n = EC_POINT_point2oct(EC_KEY_get0_group(ec), EC_KEY_get0_public_key(ec), POINT_CONVERSION_UNCOMPRESSED, out, max_out, NULL);
  EC_KEY_free(ec);
  if (n == 0) return 0;
  *out_len = n;
  return 1;
}

int kufuli_pkey_rsa_components(const void *pkey, uint8_t *n_out, size_t *n_len, size_t n_max, uint8_t *e_out, size_t *e_len,
                              size_t e_max) {
  RSA *rsa = EVP_PKEY_get1_RSA((EVP_PKEY *)pkey);
  const BIGNUM *bn_n = NULL;
  const BIGNUM *bn_e = NULL;
  int ok = 0;
  if (rsa == NULL) return 0;
  bn_n = RSA_get0_n(rsa);
  bn_e = RSA_get0_e(rsa);
  if (bn_n != NULL && bn_e != NULL && (size_t)BN_num_bytes(bn_n) <= n_max && (size_t)BN_num_bytes(bn_e) <= e_max) {
    *n_len = BN_bn2bin(bn_n, n_out);
    *e_len = BN_bn2bin(bn_e, e_out);
    ok = 1;
  }
  RSA_free(rsa);
  return ok;
}

/* Ed25519 is one-shot with a NULL digest; EC and RSA carry the hash. RSA-PSS is configured on the
 * signing ctx with a digest-length salt and MGF1 matching the digest (the JOSE/TLS profile). */
int kufuli_pkey_sign(const void *pkey, int scheme, int md, const uint8_t *data, size_t len, uint8_t *out, size_t *out_len,
                     size_t max_out) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_PKEY_CTX *pctx = NULL;
  const EVP_MD *digest = scheme == KUFULI_SCHEME_ED25519 ? NULL : md_of(md);
  size_t siglen = max_out;
  int ok = 0;
  if (mdctx == NULL) return 0;
  if (scheme != KUFULI_SCHEME_ED25519 && digest == NULL) {
    EVP_MD_CTX_free(mdctx);
    return 0;
  }
  if (EVP_DigestSignInit(mdctx, &pctx, digest, NULL, (EVP_PKEY *)pkey)) {
    int cfg = 1;
    if (scheme == KUFULI_SCHEME_RSA_PSS)
      cfg = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) &&
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) && EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, digest);
    if (cfg && EVP_DigestSign(mdctx, out, &siglen, data, len)) {
      *out_len = siglen;
      ok = 1;
    }
  }
  EVP_MD_CTX_free(mdctx);
  return ok;
}

int kufuli_pkey_verify(const void *pkey, int scheme, int md, const uint8_t *data, size_t len, const uint8_t *sig,
                       size_t sig_len) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_PKEY_CTX *pctx = NULL;
  const EVP_MD *digest = scheme == KUFULI_SCHEME_ED25519 ? NULL : md_of(md);
  int ok = 0;
  if (mdctx == NULL) return 0;
  if (scheme != KUFULI_SCHEME_ED25519 && digest == NULL) {
    EVP_MD_CTX_free(mdctx);
    return 0;
  }
  if (EVP_DigestVerifyInit(mdctx, &pctx, digest, NULL, (EVP_PKEY *)pkey)) {
    int cfg = 1;
    if (scheme == KUFULI_SCHEME_RSA_PSS)
      cfg = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) &&
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) && EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, digest);
    if (cfg) ok = EVP_DigestVerify(mdctx, sig, sig_len, data, len);
  }
  EVP_MD_CTX_free(mdctx);
  return ok;
}

int kufuli_pkey_derive(const void *priv, const void *peer_pub, uint8_t *out, size_t *out_len, size_t max_out) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY *)priv, NULL);
  size_t len = max_out;
  int ok = 0;
  if (ctx == NULL) return 0;
  if (EVP_PKEY_derive_init(ctx) && EVP_PKEY_derive_set_peer(ctx, (EVP_PKEY *)peer_pub) && EVP_PKEY_derive(ctx, out, &len)) {
    *out_len = len;
    ok = 1;
  }
  EVP_PKEY_CTX_free(ctx);
  return ok;
}

/* OAEP with the MGF1 hash pinned to the OAEP hash. aws-lc defaults the OAEP md to SHA-1, so it is
 * always set explicitly. The decrypt error is deliberately opaque (the Manger countermeasure lives
 * in aws-lc); the Scala side maps a 0 return to AuthFailed. */
int kufuli_pkey_oaep_encrypt(const void *pub, int md, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len,
                             size_t max_out) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY *)pub, NULL);
  const EVP_MD *digest = md_of(md);
  size_t len = max_out;
  int ok = 0;
  if (ctx == NULL || digest == NULL) {
    EVP_PKEY_CTX_free(ctx);
    return 0;
  }
  if (EVP_PKEY_encrypt_init(ctx) && EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) &&
      EVP_PKEY_CTX_set_rsa_oaep_md(ctx, digest) && EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, digest) &&
      EVP_PKEY_encrypt(ctx, out, &len, in, in_len)) {
    *out_len = len;
    ok = 1;
  }
  EVP_PKEY_CTX_free(ctx);
  return ok;
}

int kufuli_pkey_oaep_decrypt(const void *priv, int md, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len,
                             size_t max_out) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY *)priv, NULL);
  const EVP_MD *digest = md_of(md);
  size_t len = max_out;
  int ok = 0;
  if (ctx == NULL || digest == NULL) {
    EVP_PKEY_CTX_free(ctx);
    return 0;
  }
  if (EVP_PKEY_decrypt_init(ctx) && EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) &&
      EVP_PKEY_CTX_set_rsa_oaep_md(ctx, digest) && EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, digest) &&
      EVP_PKEY_decrypt(ctx, out, &len, in, in_len)) {
    *out_len = len;
    ok = 1;
  }
  EVP_PKEY_CTX_free(ctx);
  return ok;
}
