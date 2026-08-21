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
// The two carriers whose byte view is PUBLIC live here alone, because the file-level
// capture-checking import that makes their `Slice^` continuations enforceable also withholds the
// file from the formatters - so the cost stays off the rest of the surface. Enforcement is
// non-viral: a consumer compiled without the import sees ordinary function types.
package kufuli

import scala.annotation.targetName
import scala.language.experimental.captureChecking

import boilerplate.Secret
import boilerplate.Slice
import boilerplate.effect.Eff
import boilerplate.effect.UEff
import boilerplate.effect.useEff as secretUseEff

/** A shared secret from key agreement or KEM decapsulation, never exposed raw: the bytes are
  * reachable only inside `use` or `useEff`, and `destroy` erases them.
  */
opaque type SharedSecret = Secret
object SharedSecret:
  private[kufuli] def unsafe(bytes: Array[Byte]): SharedSecret =
    val s = Secret.fill(bytes.length) { dst =>
      val _ = Slice.of(bytes).copyInto(dst)
    }
    Slice.of(bytes).wipe()
    s
  extension (z: SharedSecret)
    private[kufuli] def read[A](f: Slice^ => A): A = Secret.use(z)(f)

    /** Borrows the live bytes for `f` under the read guard, so a concurrent `destroy` raises on its
      * own side rather than erasing mid-read.
      */
    def use[A](f: Slice^ => A): UEff[A] = Eff.suspend(Secret.use(z)(f))

    /** As [[use]], holding the guard across the returned effect rather than only across the call. */
    def useEff[E <: Throwable, A](f: Slice^ => Eff[E, A]): Eff[E, A] = secretUseEff(z)(f)
    def destroy: UEff[Unit] = Eff.suspend(Secret.destroy(z)())

    /** One-shot extract-then-expand to a key of algorithm `A` - the common non-TLS derivation. */
    def deriveKey[A <: SymmetricAlgorithm](hash: Sha2, salt: Slice, info: Slice, as: SymmetricSpec[A])(using
      KDF
    ): UEff[SecretKey[A]] =
      // The PRK is full key material and the expand can fail or be cancelled, so its destruction is
      // a finaliser rather than a step on the success path.
      HKDF.extractFrom(hash, salt, z).flatMap(prk => HKDF.expandKey(hash, prk, info, as).guarantee(prk.destroy))
  end extension
end SharedSecret

/** An HKDF pseudo-random key; wipeable and scoped like [[SharedSecret]]. */
opaque type PRK = Secret
object PRK:
  private[kufuli] def unsafe(bytes: Array[Byte]): PRK =
    val s = Secret.fill(bytes.length) { dst =>
      val _ = Slice.of(bytes).copyInto(dst)
    }
    Slice.of(bytes).wipe()
    s
  extension (p: PRK)
    private[kufuli] def read[A](f: Slice^ => A): A = Secret.use(p)(f)
    @targetName("usePrk")
    def use[A](f: Slice^ => A): UEff[A] = Eff.suspend(Secret.use(p)(f))
    @targetName("useEffPrk")
    def useEff[E <: Throwable, A](f: Slice^ => Eff[E, A]): Eff[E, A] = secretUseEff(p)(f)
    @targetName("destroyPrk")
    def destroy: UEff[Unit] = Eff.suspend(Secret.destroy(p)())
  end extension
end PRK
