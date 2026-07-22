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
package kufuli.password

import scala.scalanative.unsafe.*
import scala.scalanative.unsigned.*

import boilerplate.Slice
import boilerplate.effect.EffIO
import boilerplate.effect.UEffIO
import cats.effect.IO

import kufuli.guard

@extern
private[password] object argon2ffi:
  def argon2id_hash_raw(
    tCost: CUnsignedInt,
    mCost: CUnsignedInt,
    parallelism: CUnsignedInt,
    pwd: Ptr[Byte],
    pwdLen: CSize,
    salt: Ptr[Byte],
    saltLen: CSize,
    hash: Ptr[Byte],
    hashLen: CSize): CInt = extern
end argon2ffi

private[password] trait Argon2Platform:
  given Argon2 = new Argon2:
    def hash(password: Slice, salt: Slice, params: Argon2Params): UEffIO[Array[Byte]] =
      EffIO.liftF(guard(IO.blocking {
        val out = new Array[Byte](32)
        val rc = argon2ffi.argon2id_hash_raw(
          params.iterations.toUInt,
          params.memoryKib.toUInt,
          params.parallelism.toUInt,
          password.unsafePtr,
          password.length.toCSize,
          salt.unsafePtr,
          salt.length.toCSize,
          Slice.of(out).unsafePtr,
          32.toCSize
        )
        // Inputs are pre-validated, so a non-zero return is an anomaly; guard sanitises the raise so
        // the password never surfaces.
        if rc != 0 then throw new IllegalStateException("argon2id primitive failed unexpectedly") // scalafix:ok DisableSyntax.throw
        out
      }))
end Argon2Platform
