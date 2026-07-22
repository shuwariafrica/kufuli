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
// The node Argon2id provider is a deterministic stub, NOT real crypto - the node backend is unimplemented.
package kufuli.password

import boilerplate.Slice
import boilerplate.effect.EffIO
import boilerplate.effect.UEffIO

private[password] trait Argon2Platform:
  given Argon2 = new Argon2:
    def hash(password: Slice, salt: Slice, params: Argon2Params): UEffIO[Array[Byte]] =
      EffIO.suspend(stubArgon2(password, salt, params))

private def stubArgon2(password: Slice, salt: Slice, params: Argon2Params): Array[Byte] =
  val marker = Array[Byte](params.iterations.toByte, params.parallelism.toByte, (params.memoryKib / 1024).toByte)
  val h = Seq(password.toArray, salt.toArray, marker).flatten
    .foldLeft(0xcbf29ce484222325L)((acc, b) => (acc ^ (b & 0xff)) * 0x100000001b3L)
  Array.tabulate(32) { i =>
    val z0 = h + i + 0x9e3779b97f4a7c15L
    val z1 = (z0 ^ (z0 >>> 30)) * 0xbf58476d1ce4e5b9L
    val z2 = (z1 ^ (z1 >>> 27)) * 0x94d049bb133111ebL
    ((z2 ^ (z2 >>> 31)) & 0xff).toByte
  }
