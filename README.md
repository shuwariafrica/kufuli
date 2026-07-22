# kufuli

Cross-platform cryptography for Scala 3 on cats-effect. One API - the same source on JVM (JDK 25+),
Node.js, browsers, and Scala Native - over each platform's own engine: JCA, `node:crypto`, Web
Crypto, and aws-lc.

kufuli is misuse-resistant by design. Failures that depend on data are typed values, not exceptions;
programmer mistakes are defects. Keys are opaque and algorithm-typed, so an AEAD key cannot sign and
a P-256 key cannot verify a P-384 signature - the compiler rejects it. Where a platform provides
them, nonce-misuse-resistant AEADs (XChaCha20-Poly1305, AES-256-GCM-SIV) and first-class key rotation
remove the classic footguns.

> Status: under active development. The public API below is complete and verified on all four
> platforms; the JVM and Native backends are implemented, the JS (node and browser) backends are in
> progress.

## Install

kufuli publishes a platform-aware artifact for each target. In a cross-platform build:

```scala
libraryDependencies += "africa.shuwari" %%% "kufuli" % "<version>"
```

For a JVM-only build, use `%%`. Browser targets use the WebCrypto artifact instead of the core one:

```scala
libraryDependencies += "africa.shuwari" %%% "kufuli-browser" % "<version>"
```

The JOSE, password, and X.509 layers are separate artifacts (`kufuli-jose`, `kufuli-password`,
`kufuli-x509`) that depend on the core.

## Modules

| Artifact          | Purpose                                                            |
| ----------------- | ----------------------------------------------------------------- |
| `kufuli`          | Primitives, recipes, key rotation, and the `kufuli.unsafe` floor. |
| `kufuli-browser`  | The WebCrypto build of the core, for browser bundles.             |
| `kufuli-jose`     | JWT/JWS/JWE/JWK(S) and COSE key import.                            |
| `kufuli-password` | Argon2id password hashing with the PHC format.                    |
| `kufuli-x509`     | Certificate path validation and stapled-OCSP verification.        |

Every operation is a value in `boilerplate.effect`: `UEffIO[A]` when it cannot fail, and
`EffIO[E, A]` when `E` is its typed error. Both run as ordinary cats-effect `IO`.

## Usage

`import kufuli.*` brings in the whole core surface, including the backend evidence for the current
artifact.

### Encrypt and rotate keys

Sealing generates the nonce internally, so it can never be reused by accident. Boxes are
self-describing and versioned, and a `Keyring` makes rotation a value:

```scala
import kufuli.*

for
  key   <- AesGcm256.generate                          // or AesGcm256.key(rawBytes)
  box   <- key.seal("account-number".getBytes, aad = "user-42".getBytes)
  plain <- key.open(box, aad = "user-42".getBytes)      // EffIO[AuthFailed, Array[Byte]]
yield box.bytes                                        // the stored form; SealedBox.of parses it back
```

A `Keyring` seals under its primary key and still opens anything it holds, so rotation is a value:

```scala
for
  ring0 <- EffIO.delay(Keyring.of(KeyId.of(1) -> key))
  ring1 <- EffIO.delay(ring0.rotated(KeyId.of(2) -> newKey))
  box   <- ring1.seal(secret)                          // under the new primary; older keys still open
yield box
```

Prefer `XChaCha20Poly1305` or `AesGcmSiv256` for high-volume sealing on backends that provide them.

### Sign and verify

Algorithm-typed keys make cross-algorithm and weak-hash misuse a type error:

```scala
for
  kp  <- Ed25519.generate
  sig <- kp.privateKey.sign(message)
  _   <- kp.publicKey.verify(message, sig)                     // EffIO[SignatureRejected, Unit]
yield ()
```

### Issue and check JWTs

The `alg` fixes the key type, the audience and algorithm allowlist are required, and `alg: none` is
unrepresentable:

```scala
import kufuli.jose.*

val claims = JWT.Claims(subject = Some("user-1"), audiences = Set("api"))
val policy = JWT.Policy(audience = "api", algorithms = Set(ES256, EdDSA))

for
  kp    <- P256.generate
  token <- JWT.sign(claims, ES256)(kp.privateKey)              // only accepts a P-256 private key
  who   <- JWT.verify(token.compact, jwks, policy)             // EffIO[JWT.Rejected, JWT.Verified]
yield ()
```

### Hash passwords

Verification takes the current policy, so it can flag a hash that should be recomputed. A wrong
password is a result, not an error:

```scala
import kufuli.password.*

for
  stored  <- "correct horse battery staple".hash(Argon2Params.interactive)
  outcome <- "correct horse battery staple".verify(against = stored, policy = Argon2Params.default)
yield outcome match
  case PasswordCheck.Rejected             => // reject the login
  case PasswordCheck.Verified(Some(newer)) => // accept, then rehash under `newer`
  case PasswordCheck.Verified(None)        => // accept
```

### Drive a record protocol

For TLS/QUIC-style codecs, acquire a `Cipher` handle. Its operations are synchronous and speak
`boilerplate.Slice`, so the crypto-to-socket glue never handles a raw offset. The nonce is explicit
in both directions, and the handle enforces and reports RFC 9001 usage budgets:

```scala
key.cipher.use: c =>                                           // Resource[IO, Cipher[AesGcm256]]
  Nonce.xorInto(iv, sequence, nonceBuf, 0)                     // RFC 8446 nonce derivation
  c.encrypt(out, plaintext, aad, nonce) match
    case Right(n)             => socket.write(out.take(n))
    case Left(BudgetExhausted) => // rotate keys ahead of the limit via c.budget
```

Raw block, keystream, and QUIC header-protection primitives live in `kufuli.unsafe` for protocol
authors who own their invariants.

## Platform capabilities

The universal set - AES-GCM, HMAC, AES-KW, the CBC-HMAC composites, SHA-2 digests, HKDF, PBKDF2,
ECDSA, EdDSA, X25519, and RSA - is available everywhere. The rest is backend-dependent:

| Capability                            | JVM (JCA) | Node | Native (aws-lc) | Browser |
| ------------------------------------- | :-------: | :--: | :-------------: | :-----: |
| ChaCha20-Poly1305, AES-KWP, `Cipher`  |    yes    | yes  |       yes       |   no    |
| ML-KEM 768/1024                       |    yes    |  no  |       yes       |   no    |
| XChaCha20-Poly1305, AES-256-GCM-SIV   |    no     |  no  |       yes       |   no    |
| Argon2id                              |    yes    | yes  |       yes       |   no    |

A capability the backend lacks is a compile error at the call site, not a runtime failure. The
browser artifact is WebCrypto-only and therefore async-only: the synchronous `Cipher`, incremental
hashing, and `kufuli.unsafe` are not part of it.

## Requirements

- Scala 3.8+.
- JVM: JDK 25+ (the in-JDK JCA ML-KEM provider).
- Node.js: 24+ (Argon2id needs 24.7+).
- Scala Native: 0.5+ with a C toolchain; the native backend links aws-lc, provisioned by sbt-snx.

## Licence

MIT. Third-party components vendored as git submodules under `vendor/` retain their original licences
and are acknowledged in [`NOTICE`](NOTICE).
