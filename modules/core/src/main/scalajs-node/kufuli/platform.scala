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
// XChaCha and GCM-SIV are deliberately absent from this table: node:crypto does not expose them.
package kufuli

private[kufuli] type KeyRepr = Array[Byte]
private[kufuli] def keyRepr(bytes: Array[Byte]): KeyRepr = bytes
private[kufuli] def keyBytes(r: KeyRepr): Array[Byte] = r

private[kufuli] trait RandomPlatform extends node.RandomDefault
private[kufuli] trait AeadPlatform extends node.AeadUniversal, node.AeadChaCha
private[kufuli] trait MacPlatform extends node.MacAll
private[kufuli] trait SignerPlatform extends node.SignersAll
private[kufuli] trait VerifierPlatform extends node.VerifiersAll
private[kufuli] trait AgreementPlatform extends node.AgreementAll
private[kufuli] trait KemPlatform extends node.KemAll
private[kufuli] trait WrapPlatform extends node.WrapKw, node.WrapKwp
private[kufuli] trait KdfPlatform extends node.KdfDefault
private[kufuli] trait HashPlatform extends node.HashAll
private[kufuli] trait HashingPlatform extends node.HashingSync
private[kufuli] trait CipheringPlatform extends node.CipheringUniversal, node.CipheringChaCha
private[kufuli] trait OaepPlatform extends node.OaepDefault
private[kufuli] trait EdKeysPlatform extends node.EdKeysBytes
private[kufuli] trait XKeysPlatform extends node.XKeysBytes
private[kufuli] trait EcKeysPlatform extends node.EcKeysBytes
private[kufuli] trait RsaKeysPlatform extends node.RsaKeysBytes
private[kufuli] trait KemKeysPlatform extends node.KemKeysAll
