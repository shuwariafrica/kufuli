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
// JS-Browser backend unit (WebCrypto), shipped as its own artifact (kufuli-browser): a bundle can
// never mix node and browser crypto, so backend choice is dependency choice. WebCrypto is
// async-only (no record Cipher, no incremental Hashing) and lacks ChaCha / AES-KWP / ML-KEM.
// Public keys may be live CryptoKey handles; generated keys are non-extractable, so the
// handle-backed lifecycle makes `extractable=false` real (typed export failure) while imported
// keys export what the caller supplied. Instance bodies are the stub backend.
package kufuli

/** A live WebCrypto `CryptoKey`. `material` stands in for the key bytes the runtime holds, which
  * the backend reaches exactly as `subtle.*` reaches a handle's internal material.
  */
final class CryptoKeyHandle(private[kufuli] val material: Array[Byte])

private[kufuli] type KeyRepr = Array[Byte] | CryptoKeyHandle
private[kufuli] def keyRepr(bytes: Array[Byte]): KeyRepr = bytes
private[kufuli] def keyBytes(r: KeyRepr): Array[Byte] = r match
  case b: Array[Byte] => b
  // W3C WebCrypto fixes `generateKey`'s `extractable` to the private key alone: a public key is
  // always extractable, whatever the caller asked for.
  case h: CryptoKeyHandle => h.material

// Handle-backed secret custody: a WebCrypto private or secret key is a live CryptoKey the runtime
// owns. It has no byte view, and destroy drops the reference and flips liveness so that further use
// raises exactly as on the bytes arm - the lifecycle is universal, only the view is arm-specific.
final private[kufuli] class SecretHandle(h: CryptoKeyHandle):
  private val ref = new java.util.concurrent.atomic.AtomicReference[Option[CryptoKeyHandle]](Some(h))
  private[kufuli] def handle: CryptoKeyHandle =
    ref.get().getOrElse(throw new IllegalStateException("secret already destroyed")) // scalafix:ok DisableSyntax.throw
  private[kufuli] def material: Array[Byte] = handle.material
  private[kufuli] def kill(): Unit = ref.set(None)

private[kufuli] type SecretRepr = boilerplate.Secret | SecretHandle
private[kufuli] def secretAdopt(bytes: Array[Byte]): SecretRepr =
  val s = boilerplate.Secret.fill(bytes.length) { dst =>
    val _ = boilerplate.Slice.of(bytes).copyInto(dst)
  }
  boilerplate.Slice.of(bytes).wipe()
  s
private[kufuli] def secretCopy(bytes: Array[Byte]): SecretRepr =
  boilerplate.Secret.fill(bytes.length) { dst =>
    val _ = boilerplate.Slice.of(bytes).copyInto(dst)
  }
private[kufuli] def secretRead[B](r: SecretRepr)(f: boilerplate.Slice => B): B = r match
  case s: boilerplate.Secret => boilerplate.Secret.use(s)(f)
  case h: SecretHandle       =>
    val _ = h.handle // liveness first, so a destroyed handle reports destruction rather than absence
    throw new IllegalStateException("handle-backed key has no byte view") // scalafix:ok DisableSyntax.throw
private[kufuli] def secretDestroy(r: SecretRepr): Unit = r match
  case s: boilerplate.Secret => boilerplate.Secret.destroy(s)()
  case h: SecretHandle       => h.kill()

// WebCrypto generation yields live handles: the private key non-extractable, the public key one that
// always exports.
private[kufuli] def secretGenerated(bytes: Array[Byte]): SecretRepr = new SecretHandle(new CryptoKeyHandle(bytes))
private[kufuli] def keyGenerated(bytes: Array[Byte]): KeyRepr = new CryptoKeyHandle(bytes)
private[kufuli] def secretExportable(r: SecretRepr): Boolean = r match
  case _: boilerplate.Secret => true
  case _: SecretHandle       => false

// The BACKEND door: an operation on a handle routes the handle; the shared byte view keeps raising.
private[kufuli] def secretMaterial[B](r: SecretRepr)(f: boilerplate.Slice => B): B = r match
  case s: boilerplate.Secret => boilerplate.Secret.use(s)(f)
  case h: SecretHandle       => f(boilerplate.Slice.of(h.material))

private[kufuli] trait RandomPlatform extends stubs.RandomDefault
private[kufuli] trait AeadPlatform extends stubs.AeadUniversal // no ChaCha in WebCrypto
private[kufuli] trait MacPlatform extends stubs.MacAll
private[kufuli] trait SigningPlatform extends stubs.SignersAll
private[kufuli] trait VerifyingPlatform extends stubs.VerifiersAll
private[kufuli] trait AgreementPlatform extends stubs.AgreementAll
private[kufuli] trait KemPlatform // no WebCrypto ML-KEM
private[kufuli] trait WrapPlatform extends stubs.WrapKw // AES-KW only, no KWP
private[kufuli] trait KdfPlatform extends stubs.KdfDefault
private[kufuli] trait HashPlatform extends stubs.HashAll
private[kufuli] trait HashingPlatform // async-only: no incremental hashing
private[kufuli] trait CipheringPlatform // async-only: no record machine
private[kufuli] trait OaepPlatform extends stubs.OaepDefault
private[kufuli] trait EdKeysPlatform extends stubs.EdKeysAll
private[kufuli] trait XKeysPlatform extends stubs.XKeysAll
private[kufuli] trait EcKeysPlatform extends stubs.EcKeysAll
private[kufuli] trait RsaKeysPlatform extends stubs.RsaKeysAll
private[kufuli] trait KemKeysPlatform // no WebCrypto ML-KEM
