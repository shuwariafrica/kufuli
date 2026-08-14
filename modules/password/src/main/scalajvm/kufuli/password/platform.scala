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
// JVM Argon2id provider (BouncyCastle). BouncyCastle is password-module + JVM-only; core never
// depends on it. Argon2id is memory-hard (ms-class), so hashing runs on the blocking pool.
package kufuli.password

import boilerplate.Slice
import boilerplate.effect.Eff
import boilerplate.effect.UEff
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

private[kufuli] trait Argon2Platform:
  given Argon2 = new Argon2:
    private[kufuli] def hash(password: Slice, salt: Slice, params: Argon2Params): UEff[Array[Byte]] =
      Eff.suspendBlocking {
        val p = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
          .withVersion(Argon2Parameters.ARGON2_VERSION_13)
          .withIterations(params.iterations)
          .withMemoryAsKB(params.memoryKib)
          .withParallelism(params.parallelism)
          .withSalt(salt.toArray)
          .build()
        val gen = new Argon2BytesGenerator
        gen.init(p)
        val out = new Array[Byte](32)
        val _ = gen.generateBytes(password.toArray, out)
        out
      }
end Argon2Platform
