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
// Native backend unit (aws-lc): bytes-backed keys; the primary platform carries the fullest set.
// XChaCha20-Poly1305 and AES-256-GCM-SIV are aws-lc EVP_AEADs; ML-KEM is FIPS 203 in aws-lc. This
// file is the Native capability table; instance bodies are the real aws-lc backend (`awslc.scala`).
package kufuli

private[kufuli] type KeyRepr = Array[Byte]
private[kufuli] def keyRepr(bytes: Array[Byte]): KeyRepr = bytes
private[kufuli] def keyBytes(r: KeyRepr): Array[Byte] = r

private[kufuli] trait RandomPlatform extends awslc.RandomDefault
private[kufuli] trait AeadPlatform extends awslc.AeadUniversal, awslc.AeadChaCha, awslc.AeadMisuseResistant
private[kufuli] trait MacPlatform extends awslc.MacAll
private[kufuli] trait SignerPlatform extends awslc.SignersAll
private[kufuli] trait VerifierPlatform extends awslc.VerifiersAll
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
