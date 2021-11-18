# Changelog

Entries are listed in reverse chronological order.

## Unreleased

* Fixed a bug where small-order verification keys (including the identity) were
  handled inconsistently: the `VerificationKey` parsing logic rejected them, but
  the identity `VerificationKey` could be produced from the zero `SigningKey`.
  The behaviour is now to consistently accept all small-order verification keys,
  matching the RedDSA specification.

  * Downstream users who currently rely on the inconsistent behaviour (for e.g.
    consensus compatibility, either explicitly wanting to reject small-order
    verification keys, or on the belief that this crate implemented the RedDSA
    specification) should continue to use previous versions of this crate, until
    they can either move the checks into their own code, or migrate their
    consensus rules to match the RedDSA specification.

## 0.4.0

* Upgrade `rand` to 0.8, `rand_core` to 0.6, and `rand_chacha` to 0.3, together
  (#55)
* Migrate to `jubjub 0.6` (#59)
* Derive `Debug, PartialEq` (#67)
* Restrict the maximum number of FROST participants to 255 by using `u8` (#66)

## 0.3.0

* Initial support for FROST (Flexible Round-Optimized Schnorr Threshold)
  signatures.

## 0.2.2

* Make `batch::Item: Clone + Debug` and add `batch::Item::verify_single`
  for fallback verification when batch verification fails.

## 0.2.1

* Update `Cargo.toml` metadata.

## 0.2.0

* Change terminology to "signing key" and "verification key" from "secret key"
  and "public key".
* Adds a batch verification implementation which can process both binding and
  spend authorization signatures in the same batch.

## 0.1.1

* Explicitly document the consensus checks performed by
  `impl TryFrom<PublicKeyBytes<T>> for PublicKey<T>`.
* Add a test that small-order public keys are rejected.
* Add `html_root_url` to ensure cross-rendering docs works correctly (thanks
  @QuietMisdreavus).

## 0.1.0

* Initial release.
