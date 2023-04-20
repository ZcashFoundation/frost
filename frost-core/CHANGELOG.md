# Changelog

Entries are listed in reverse chronological order.

## Unreleased

## 0.3.0

* add split_key()
* rename reconstruct_secret() to reconstruct_key(), make it return SigningKey,
  fix it to return Error instead of a error string
* change SigningKey::new() to take a reference instead of a value

## 0.2.0

* Implement Zeroize where needed or skip where not needed (fixes compiling error) (#301)
* Change keygen_with_dealer() to return a HashMap (#288)
* Re-export the frost-core traits and rand-core as part of top-level impls API (#297)

## 0.1.0

* Initial release.
