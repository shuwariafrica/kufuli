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
// JVM capability table (JCA, floor JDK 25 for ML-KEM via JEP 496). XChaCha and GCM-SIV are absent
// from JCA, and core takes no BouncyCastle dependency - BC is the password module's alone.
package kufuli

private[kufuli] type KeyRepr = Array[Byte]
private[kufuli] def keyRepr(bytes: Array[Byte]): KeyRepr = bytes
private[kufuli] def keyBytes(r: KeyRepr): Array[Byte] = r

private[kufuli] trait RandomPlatform extends jca.RandomDefault
private[kufuli] trait AeadPlatform extends jca.AeadUniversal, jca.AeadChaCha
private[kufuli] trait MacPlatform extends jca.MacAll
private[kufuli] trait SignerPlatform extends jca.SignersAll
private[kufuli] trait VerifierPlatform extends jca.VerifiersAll
private[kufuli] trait AgreementPlatform extends jca.AgreementAll
private[kufuli] trait KemPlatform extends jca.KemAll
private[kufuli] trait WrapPlatform extends jca.WrapKw, jca.WrapKwp
private[kufuli] trait KdfPlatform extends jca.KdfDefault
private[kufuli] trait HashPlatform extends jca.HashAll
private[kufuli] trait HashingPlatform extends jca.HashingSync
private[kufuli] trait CipheringPlatform extends jca.CipheringUniversal, jca.CipheringChaCha
private[kufuli] trait OaepPlatform extends jca.OaepDefault
private[kufuli] trait EdKeysPlatform extends jca.EdKeysJca
private[kufuli] trait XKeysPlatform extends jca.XKeysJca
private[kufuli] trait EcKeysPlatform extends jca.EcKeysJca
private[kufuli] trait RsaKeysPlatform extends jca.RsaKeysJca
private[kufuli] trait KemKeysPlatform extends jca.KemKeysJca
