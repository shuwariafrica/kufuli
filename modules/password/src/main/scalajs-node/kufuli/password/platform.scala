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
// Node Argon2id provider over `crypto.argon2` (Node >= 24.7); memory-hard, so it runs on node's
// async threadpool. This source set is the node row alone: a hard `node:crypto` import must not
// reach a browser artifact if this module ever grows one, as core's already has.
package kufuli.password

import scala.scalajs.js
import scala.scalajs.js.annotation.JSImport
import scala.scalajs.js.typedarray.Uint8Array

import boilerplate.Slice
import boilerplate.effect.EffIO
import boilerplate.effect.UEffIO
import boilerplate.nullable.option
import cats.effect.IO

import kufuli.guard
import kufuli.nodecrypto.ba
import kufuli.nodecrypto.u8

private[password] object nodeArgon2:
  // `crypto.argon2` is outside core's facade because core has no password tier; the byte
  // converters are core's, so there is one copy point for the whole JS artifact.
  @js.native
  @JSImport("node:crypto", JSImport.Default)
  private[password] object crypto extends js.Object:
    def argon2(algorithm: String, options: js.Any, callback: js.Function2[js.Error | Null, Uint8Array, Unit]): Unit = js.native

private[password] trait Argon2Platform:
  given Argon2 = new Argon2:
    def hash(password: Slice, salt: Slice, params: Argon2Params): UEffIO[Array[Byte]] =
      EffIO.liftF(guard(IO.async_[Array[Byte]] { cb =>
        nodeArgon2.crypto.argon2(
          "argon2id",
          js.Dynamic.literal(
            message = u8(password.toArray),
            nonce = u8(salt.toArray),
            parallelism = params.parallelism,
            tagLength = 32,
            memory = params.memoryKib,
            passes = params.iterations
          ),
          (err, out) =>
            err.option match
              case None    => cb(Right(ba(out)))
              case Some(e) => cb(Left(js.JavaScriptException(e)))
        )
      }))
end Argon2Platform
