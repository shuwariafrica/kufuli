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
package kufuli.unsafe

import scala.scalanative.unsigned.*

import boilerplate.Slice

import kufuli.awslcffi

private[unsafe] def aesBlockEncrypt(key: Array[Byte], src: Slice, dst: Slice): Unit =
  require(
    awslcffi.kufuli_aes_block_encrypt(dst.unsafePtr, src.unsafePtr, Slice.of(key).unsafePtr, key.length.toCSize) == 1,
    "aes block"
  )

private[unsafe] def chacha20Keystream(key: Array[Byte], dst: Slice, nonce: Slice, counter: Int): Unit =
  require(
    awslcffi.kufuli_chacha20_keystream(dst.unsafePtr, dst.length.toCSize, Slice.of(key).unsafePtr, nonce.unsafePtr, counter.toUInt) == 1,
    "chacha20 keystream"
  )
