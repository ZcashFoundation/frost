# Changelog

Entries are listed in reverse chronological order.


## Unreleased


## 3.0.0

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
