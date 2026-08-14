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
// Native capability table (aws-lc). It carries the widest set: XChaCha20-Poly1305 and
// AES-256-GCM-SIV are aws-lc EVP_AEADs, available on no other backend.
package kufuli

private[kufuli] type KeyRepr = Array[Byte]
private[kufuli] def keyRepr(bytes: Array[Byte]): KeyRepr = bytes
private[kufuli] def keyBytes(r: KeyRepr): Array[Byte] = r

// Bytes-backed secret custody: the carrier is boilerplate's guarded Secret. `secretAdopt` TRANSFERS
// custody of a kufuli-internal transient (copy in, wipe the source); `secretCopy` copies a
// caller-owned buffer and leaves its hygiene to the caller.
private[kufuli] type SecretRepr = boilerplate.Secret
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
private[kufuli] def secretRead[B](r: SecretRepr)(f: boilerplate.Slice => B): B = boilerplate.Secret.use(r)(f)
private[kufuli] def secretDestroy(r: SecretRepr): Unit = boilerplate.Secret.destroy(r)()

// Generated keys are byte-backed and exportable here, so the backend door coincides with the view.
private[kufuli] def secretGenerated(bytes: Array[Byte]): SecretRepr = secretAdopt(bytes)
private[kufuli] def keyGenerated(bytes: Array[Byte]): KeyRepr = bytes
private[kufuli] def secretExportable(r: SecretRepr): Boolean =
  val _ = r
  true
private[kufuli] def secretMaterial[B](r: SecretRepr)(f: boilerplate.Slice => B): B = boilerplate.Secret.use(r)(f)

private[kufuli] trait RandomPlatform extends awslc.RandomDefault
private[kufuli] trait AeadPlatform extends awslc.AeadUniversal, awslc.AeadChaCha, awslc.AeadMisuseResistant
private[kufuli] trait MacPlatform extends awslc.MacAll
private[kufuli] trait SigningPlatform extends awslc.SignersAll
private[kufuli] trait VerifyingPlatform extends awslc.VerifiersAll
private[kufuli] trait AgreementPlatform extends awslc.AgreementAll
private[kufuli] trait KemPlatform extends awslc.KemAll
private[kufuli] trait WrapPlatform extends awslc.WrapKw, awslc.WrapKwp
private[kufuli] trait KdfPlatform extends awslc.KdfDefault
private[kufuli] trait HashPlatform extends awslc.HashAll
private[kufuli] trait HashingPlatform extends awslc.HashingSync
private[kufuli] trait CipheringPlatform extends awslc.CipheringUniversal, awslc.CipheringChaCha, awslc.CipheringMisuseResistant
private[kufuli] trait OaepPlatform extends awslc.OaepDefault
private[kufuli] trait EdKeysPlatform extends awslc.EdKeysBytes
private[kufuli] trait XKeysPlatform extends awslc.XKeysBytes
private[kufuli] trait EcKeysPlatform extends awslc.EcKeysBytes
private[kufuli] trait RsaKeysPlatform extends awslc.RsaKeysBytes
private[kufuli] trait KemKeysPlatform extends awslc.KemKeysAll
