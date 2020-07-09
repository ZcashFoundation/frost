# Changelog

Entries are listed in reverse chronological order.

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
