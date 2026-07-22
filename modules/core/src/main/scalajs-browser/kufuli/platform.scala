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

// Placeholder for a browser WebCrypto CryptoKey handle.
final class CryptoKeyHandle

private[kufuli] type KeyRepr = Array[Byte] | CryptoKeyHandle
private[kufuli] def keyRepr(bytes: Array[Byte]): KeyRepr = bytes
private[kufuli] def keyBytes(r: KeyRepr): Array[Byte] = r match
  case b: Array[Byte]     => b
  case _: CryptoKeyHandle => Array.emptyByteArray // stub: handle-only keys never reach a byte op here

private[kufuli] trait RandomPlatform extends stubs.RandomDefault
private[kufuli] trait AeadPlatform extends stubs.AeadUniversal // no ChaCha in WebCrypto
private[kufuli] trait MacPlatform extends stubs.MacAll
private[kufuli] trait SignerPlatform extends stubs.SignersAll
private[kufuli] trait VerifierPlatform extends stubs.VerifiersAll
private[kufuli] trait AgreementPlatform extends stubs.AgreementAll
private[kufuli] trait KemPlatform // no WebCrypto ML-KEM
private[kufuli] trait WrapPlatform extends stubs.WrapKw // AES-KW only, no KWP
private[kufuli] trait KdfPlatform extends stubs.KdfDefault
private[kufuli] trait HashPlatform extends stubs.HashAll
private[kufuli] trait HashingPlatform // async-only: no incremental hashing
private[kufuli] trait CipheringPlatform // async-only: no record machine
private[kufuli] trait OaepPlatform extends stubs.OaepDefault
private[kufuli] trait EdKeysPlatform extends stubs.EdKeysHandles
private[kufuli] trait XKeysPlatform extends stubs.XKeysHandles
private[kufuli] trait EcKeysPlatform extends stubs.EcKeysHandles
private[kufuli] trait RsaKeysPlatform extends stubs.RsaKeysHandles
private[kufuli] trait KemKeysPlatform // no WebCrypto ML-KEM
