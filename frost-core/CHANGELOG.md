# Changelog

Entries are listed in reverse chronological order.

## 2.2.0

### Security Fixes

* Added validation for the `min_signers` parameter in the
  `frost_core::keys::refresh` functions. It was not clear that it is not
  possible to change `min_signers` with the refresh procedure. Using a smaller
  value would not decrease the threshold, and attempts to sign using a smaller
  threshold would fail. Additionally, after refreshing the shares with a smaller
  threshold, it would still be possible to sign with the original threshold;
  however, this could cause a security loss to the participant's shares. We have
  not determined the exact security implications of doing so and judged simpler
  to just validate `min_signers`. If for some reason you have done a refresh
  share procedure with a smaller `min_signers` we strongly recommend migrating
  to a new key. Thank you [BlockSec](https://blocksec.com/) for reporting the
  finding.

### Other Changes

* MSRV has been bumped to Rust 1.81, making all crates no-std (except
  `frost-ed448`).
* Added DKG refresh functions to the crate-specific `refresh` modules.
* Added `VerifiableSecretSharingCommitment::{serialize,deserialize}_whole()`
  methods.
* Added `Ciphersuite::post_generate()` method to allow more ciphersuite
  customization.

## 2.1.0

* It is now possible to identify the culprit in `frost_core::keys::dkg::part3()`
  if an invalid secret share was sent by one of the participants (by calling
  `frost_core::Error<C>::culprit()`) (#728)
* Added frost-secp256k1-tr crate, allowing to generate Bitcoin Taproot
  (BIP340/BIP341) compatible signatures (#730).
* Support refreshing shares using the DKG approach using the
  `frost_core::keys::refresh::refresh_dkg_{part1,part2,shares}()` functions
  (#766).
* `frost_core::keys::dkg::part{1,2}::SecretPackage` are now serializable (#833).

## 2.0.0

* Updated docs
* Added missing `derive(Getters)` for `dkg::{round1, round2}`
* Added `internal` feature for `validate_num_of_signers`
* Added refresh share functionality for trusted dealer:
  `frost_core::keys::refresh::{compute_refreshing_shares, refresh_share}`
* Added a `'static` bound to the `Ciphersuite` trait. This is a breaking change,
  but it's likely to not require any code changes since most ciphersuite
  implementations are probably just empty structs. The bound makes it possible
  to use `frost_core::Error<C>` in `Box<dyn std::error::Error>`.
* Added getters to `round1::SecretPackage` and `round2::SecretPackage`.
* Added a `frost_core::verify_signature_share()` function which allows verifying
  individual signature shares. This is not required for regular FROST usage but
  might useful in certain situations where it is desired to verify each
  individual signature share before aggregating the signature.

## 2.0.0-rc.0

* Changed the `deserialize()` function of Elements and structs containing
  Elements to return an error if the element is the identity. This is a
  requirement in the FROST specification that wasn't being followed. We are not
  aware of any possible security issues that could be caused by this; in the
  unlikely case that the identity was being serialized, this would be caught by
  deserialization methods. However, we consider this change the right thing to
  do as a defense-in-depth mechanism. This entails the following changes:
  * `Group::serialize()` now returns an error. When implementing it, you must
    return an error if it attempts to serialize the identity.
  * `VerifyingShare::serialize()`, `CoefficientCommitment::serialize()`,
    `VerifiableSecretSharingCommitment::serialize()`,
    `NonceCommitment::serialize()`, `Signature::serialize()`,
    `VerifyingKey::serialize()` can now all return an error.
* Changed the `serialize()` and `deserialize()` methods of all Scalar- and
  Element-wrapping structs; instead of taking or returning a
  `Field::Serialization` or `Element::Serialization` trait (which are usually
  defined by ciphersuites as arrays of specific sizes), they simply respectively
  take `&[u8]` and return `Vec<u8>`, exactly as the other structs, which should
  greatly simplify non-serde serialization code. You can port existing code with
  e.g. `x.serialize().as_ref()` -> `x.serialize()` and
  `X::deserialize(bytes.try_into().unwrap())` -> `X::deserialize(&bytes)`.
* Removed the `ops::{Mul, MulAssign, Sub}` implementation for `Identifier`.
  These were being used internally, but library users shouldn't need to use them.
  If you have low-level code that relied on it, use `Identifier::{new,
  to_scalar}` to handle the underlying scalar.
* Removed `batch::Item::into()` which created a batch Item from a triple of
  VerifyingKey, Signature and message. Use the new `batch::Item::new()` instead
  (which can return an error).
* Add no-std support to all crates except frost-ed448. To use, do not enable the
  `std` feature that is enabled by default (i.e. use `default-features =
  false`); Note that it always links to an external `alloc` crate (i.e. there is
  no `alloc` feature). When disabling `std`, the only impact in the API is that
  `Error` will no longer implement the `std::error::Error` trait. This is a
  breaking change if you are disabling default features but rely on `Error`
  implementing `std::error::Error`. In that case, simply enable the `std`
  feature.
* Fixed `no-default-features`, previously it wouldn't compile.
* Fixed some feature handling that would include unneeded dependencies in some
  cases.

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
