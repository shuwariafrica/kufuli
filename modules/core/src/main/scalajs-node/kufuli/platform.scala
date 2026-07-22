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
// JS-Node capability table: bytes-backed keys over the stub backend. ML-KEM, XChaCha and GCM-SIV
// are absent here - their node:crypto surface is unverified.
package kufuli

private[kufuli] type KeyRepr = Array[Byte]
private[kufuli] def keyRepr(bytes: Array[Byte]): KeyRepr = bytes
private[kufuli] def keyBytes(r: KeyRepr): Array[Byte] = r

private[kufuli] trait RandomPlatform extends stubs.RandomDefault
private[kufuli] trait AeadPlatform extends stubs.AeadUniversal, stubs.AeadChaCha
private[kufuli] trait MacPlatform extends stubs.MacAll
private[kufuli] trait SignerPlatform extends stubs.SignersAll
private[kufuli] trait VerifierPlatform extends stubs.VerifiersAll
private[kufuli] trait AgreementPlatform extends stubs.AgreementAll
private[kufuli] trait KemPlatform // no ML-KEM (node:crypto surface unverified)
private[kufuli] trait WrapPlatform extends stubs.WrapKw, stubs.WrapKwp
private[kufuli] trait KdfPlatform extends stubs.KdfDefault
private[kufuli] trait HashPlatform extends stubs.HashAll
private[kufuli] trait HashingPlatform extends stubs.HashingSync
private[kufuli] trait CipheringPlatform extends stubs.CipheringUniversal, stubs.CipheringChaCha
private[kufuli] trait OaepPlatform extends stubs.OaepDefault
private[kufuli] trait EdKeysPlatform extends stubs.EdKeysBytes
private[kufuli] trait XKeysPlatform extends stubs.XKeysBytes
private[kufuli] trait EcKeysPlatform extends stubs.EcKeysBytes
private[kufuli] trait RsaKeysPlatform extends stubs.RsaKeysBytes
private[kufuli] trait KemKeysPlatform // no ML-KEM (node:crypto surface unverified)
