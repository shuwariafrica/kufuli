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
import boilerplate.effect.UEff
import boilerplate.nullable.option
import cats.effect.IO

import kufuli.guard
import kufuli.nodecrypto.ba
import kufuli.nodecrypto.u8
import kufuli.nodecrypto.zero

private[password] object nodeArgon2:
  // `crypto.argon2` is outside core's facade because core has no password tier; the byte
  // converters are core's, so there is one copy point for the whole JS artifact.
  @js.native
  @JSImport("node:crypto", JSImport.Default)
  private[password] object crypto extends js.Object:
    def argon2(algorithm: String, options: js.Any, callback: js.Function2[js.Error | Null, Uint8Array, Unit]): Unit = js.native

private[kufuli] trait Argon2Platform:
  given Argon2 = new Argon2:
    private[kufuli] def hash(password: Slice, salt: Slice, params: Argon2Params, length: Int): UEff[Array[Byte]] =
      guard(IO.async_[Array[Byte]] { cb =>
        // Two plaintext password copies exist (the Scala array and the JS buffer); the array is
        // erased as soon as the buffer holds it, the buffer once the primitive answers - and on
        // a synchronous throw from the binding.
        val pw = password.toArray
        val buf = u8(pw)
        Slice.of(pw).wipe()
        try
          nodeArgon2.crypto.argon2(
            "argon2id",
            js.Dynamic.literal(
              message = buf,
              nonce = u8(salt.toArray),
              parallelism = params.parallelism,
              tagLength = length,
              memory = params.memoryKib,
              passes = params.iterations
            ),
            (err, out) =>
              zero(buf)
              err.option match
                // The tag is the derived key on the `deriveKey` path, so node's own buffer is
                // erased once the array copy holds it rather than left to the collector.
                case None =>
                  val tag = ba(out)
                  zero(out)
                  cb(Right(tag))
                case Some(e) => cb(Left(js.JavaScriptException(e)))
          )
        catch
          case t: Throwable =>
            zero(buf)
            throw t // scalafix:ok DisableSyntax.throw
        end try
      })
end Argon2Platform
