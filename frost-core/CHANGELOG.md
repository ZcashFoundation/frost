# Changelog

Entries are listed in reverse chronological order.

## Unreleased

## Released

## 1.0.0

* Exposed the `SigningKey::from_scalar()` and `to_scalar()` methods. This
  helps interoperability with other implementations.
* Exposed the `SigningNonces::from_nonces()` method to allow it to be
  deserialized.
* Fixed bug that prevented deserialization with in some cases (e.g. JSON
  containing escape codes).
* Added `new()` methods for `VerifirableSecretSharingCommitment` and
  `CoefficientCommitment`.

## 1.0.0-rc.0

* The `frost-core::frost` module contents were merged into `frost-core`, thus
  eliminating the `frost` module. You can adapt any calling code with e.g.
  changing `use frost_core::frost::*` to `use frost-core::*`.
* `Challenge`, `BindingFactor`, `BindingFactorList` and `GroupCommitment`
  are no longer public (you can use them with the `internals` feature).
* Both serde serialization and the default byte-oriented serialization now
  include a version field (a u8) at the beginning which is always 0 for now. The
  ciphersuite ID field was moved from the last field to the second field, after
  the version. Both version and ciphersuite ID are now grouped into a "header"
  struct, which affects self-describing formats like JSON. The ciphersuite ID
  string was also changed for all ciphersuites: it is now equal to the
  `contextString` of each ciphersuite per the FROST spec.
* Add an option to disable cheater detection during aggregation of signatures.
* Add `PublicKeyPackage::from_commitment()` and
  `PublicKeyPackage::from_dkg_commitments` to create a `PublicKeyPackage` from
  the commitments generated in trusted dealer or distributed key generation.
* Ciphersuite crates now re-export `serde` if enabled.
* Convert all `HashMaps` to `BTreeMaps`.
* Update some field names in `KeyPackage`, `Package`, `SecretShare` and `PublicKeyPackage`.
* Add generate Randomizer by hashing `SigningPackage`
* Add postcard-serde-encoded serialization as the default
* Remove `BindingFactor::deserialize()` and `BindingFactorList::iter()`

## 0.7.0

* Challenge hashing during DKG computation was changed to match the paper.
  This means that code running this version won't interoperate with code
  running previous versions.
* A new `min_signers` field was added to `KeyPackage`, which changes its
  `new()` method and its serde serialization.
* `reconstruct()` was changed to take a slice of `KeyPackage`s instead of
  `SecretShare`s since users are expect to store the former and not the latter.
* New `serialize()`/`deserialize()` methods were added so that a default
  byte-oriented serialization is available for all structs that need to be
  communicated. It is still possible to use serde with you own encoder. Note
  that the format will likely change in the next release.
* Audit findings were addressed.


## 0.6.0

* The following structs had a `Identifier` field removed, which affects
  how they are encoded and instantiated:
  * `dkg::round1::Package`
  * `dkg::round2::Package`
  * `SigningCommitments`
  * `SignatureShare`
* The following functions and methods changed parameters from `Vec` to `HashMap`
  so that callers need to indicate the identifier of the source of each
  value being passed:
  * `aggregate()`
  * `dkg::part2()`
  * `dkg::part3()`
  * `SigningPackage::new()`
* `commit()` and `preprocess()` no longer take an identifier as input
* `SignatureResponse` was removed. `SignatureShare` can now be encoded directly with
  `from/to_bytes()`.
* rename all `to_bytes()`/`from_bytes()` to `serialize()`/`deserialize()`
* The group public key is now included in the hash inside the binding factor
  computation. This reflects an upcoming change to the specification:
  https://github.com/cfrg/draft-irtf-cfrg-frost/pull/439
* `generate_with_dealer()` was change to allow specifying which identifiers to use
* Identifiers can now be derived from arbitrary strings with `Identifier::derive()`
* Added `RandomizerParams::from_randomizer()` to allow specifying a randomizer
* Added `Error::culprit()` to easily get the identifier of a misbehaving participant
* Most public types now implement common traits such as Clone and Debug

## 0.5.0

* expose SigningShare, VerifyingShare, NonceCommitment and SignatureResponse in ciphersuite libraries
* most structs now have a private field which mean that they can no longer be
  instantiated directly. `new()` methods have been added to them.
* change `SigningPackage::new()` to take `&[u8]P  instead of `Vec<u8>`
* add `serde` support under `serde` feature to allow encoding structs which
  need to be communicated between participants.
* expand docs to show the overall structure and contents

## 0.4.0

* add serialize and deserialize functions for VerifiableSecretSharingCommitment
* add value, serialize and deserialize functions for CoefficientCommitment

## 0.3.0

* add multiscalar support to speed up signing and aggregating
* change errors caused by protocol violations to contain the misbehaving party
* add frost::keys::split()
* rename reconstruct_secret() to reconstruct(), make it takes a slice instead
  of a Vector, make it return SigningKey, fix it to return Error instead of an
  error string
* rename keygen_with_dealer() to generate_with_dealer()
* change SigningKey::new() to take a reference instead of a value

## 0.2.0

* Implement Zeroize where needed or skip where not needed (fixes compiling error) (#301)
* Change keygen_with_dealer() to return a HashMap (#288)
* Re-export the frost-core traits and rand-core as part of top-level impls API (#297)

## 0.1.0

* Initial release.
