# Changelog

Entries are listed in reverse chronological order.


## Unreleased


## 3.0.0

### Breaking Changes

* The `cheater-detection` feature was removed. If you relied on it (either by
  using the default features, or by explicitly enabling it), then you don't have
  to do anything (other than not enabling it explicitly if you were doing so);
  the default behaviour is now as if `cheater-detection` was enabled. If you
  explicitly *did not enable* it, you can avoid cheater detection by calling
  `aggregate_custom()` with `CheaterDetection::Disabled`.

### Added

There is a new revamped API which was motivated by integration with Zcash
but should have broader application.

- Added `RandomizedParams::new_from_commitments()` which will generate the
  randomizer based on the signing commitments and on some fresh random data.
  This is better since all parties will contribute to the randomness of the
  randomizer. The random data ("seed") will be returned along with the
  `RandomizedParams`.
- Added `RandomizedParams::regenerate_from_seed_and_commitments()` which will
  redo the procedure above with a given seed.
- Added `sign_with_randomizer_seed()` which is a helper function that will
  rebuild the `RandomizedParams` with a given seed and proceed with the
  signing.
- Added `Randomizer::{new_from_commitments(), regenerate_from_seed_and_commitments()}`
  which are used by the above and will probably not need to be called directly.
