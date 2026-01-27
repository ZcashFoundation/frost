# Release Checklist

## One-time `gh` setup

Install the [GitHub command line
tool](https://github.com/cli/cli?tab=readme-ov-file#installation) to make
releases easier.

## One-time crates.io setup

- Follow the steps in <https://doc.rust-lang.org/cargo/reference/publishing.html#before-your-first-publish> (you can create a token scoped to `publish-update`).
- To get permissions to publish you’ll need to be in the [owners](https://github.com/orgs/ZcashFoundation/teams/owners) group. If you aren’t in there, ask someone in that group to add you


## Communication

- Post in #frost slack channel and tag the Frost team that you’re going to be doing a release to freeze PR approvals until it’s done. E.g “@frost-core I’m doing a release of \<version> of Frost. Please do not merge any more PRs until I’m finished. Thanks.”


## Checks

- Currently all crates share the same version number, in the root Cargo.toml
   file. Take note of that version. (If we ever decide to have specific
   versions, update those separately as required.)

- Decide which version to tag the release with (e.g. v0.3.0), considering
   [SemVer](https://doc.rust-lang.org/cargo/reference/semver.html). Run `cargo
   semver-checks` to check if there are no API changes that break SemVer
   compatibility. ([Installation
   instructions](https://crates.io/crates/cargo-semver-checks)) Fix issues if
   any (i.e. change the version, or revert/adapt the API change).

- Create new issue. E.g. [Release v0.4.0](https://github.com/ZcashFoundation/frost/issues/377)


## Make changes

- Bump the version of the crates in the root Cargo.toml file. (If they ever
   get out of sync, you will need to bump in each crate Cargo.toml file.)

- Bump the version used in the tutorial (importing.md)

- Check if the [changelog](https://github.com/ZcashFoundation/frost/blob/main/frost-core/CHANGELOG.md) is up to date and update if required (we’re only keeping the one in frost-core for now). Double check using [FROST releases](https://github.com/ZcashFoundation/frost/releases) which will have a list of all the PRs that have been closed since the last release. Things to include in the changelog will be anything that impacts production code and big documentation changes. I.e. script and test changes should not be included. NOTE: Please add to the changelog whenever you make changes to the library as this will make things simpler for the person in charge of the release.

   - Move version in changelog to Released
   - Create a new version in “unreleased” in changelog

- Update the version number for frost-core and frost-rerandomized in the root Cargo.toml file, e.g. in `frost-core = { path = "frost-core", version = "0.4.0", default-features = false }`

- Create a PR with subject `Release \<version number>` containing all these changes

- You’ll need someone to review and approve it

- Wait for it to pass CI checks


## Publish

- Checkout main branch, **in the commit of the previously merged PR** (in case other stuff got merged after that)

- Run `cargo publish -p frost-core --dry-run` to check if it’s ready to publish. Fix issues if any.

- [Draft and publish a new release](https://github.com/ZcashFoundation/frost/releases/new) for frost-core.

    - In “Choose a tag” type `<crate>/<version>` e.g. “frost-core/v0.2.0” and click “Create new tag”
    - In “Target” select “main” as long as other PRs haven’t been merged after the version bump PR. Otherwise, **select the commit matching the PR that was merged above**.
    - In “Release title” use `<crate> <version>` e.g. “frost-core v0.2.0”
    - Paste the (raw Markdown) changelog for this version into the description box.
    - Leave “Set as pre-release” **unchecked** (we should have checked it in earlier versions but the ship has sailed. It doesn’t matter much)
    - **Check** “Set as the latest release”

- Publish it with `cargo publish -p frost-core`

- Check if frost-rerandomized is ready to be published: `cargo publish -p frost-rerandomized --dry-run`. Fix any errors if needed.

- Draft and publish a frost-rerandomized release:

    - Run `gh release create "frost-rerandomized/v2.1.0" -n '' -t "frost-rerandomized v2.1.0" --latest=false`
       (replace both instances of the version)

- Publish it with `cargo publish -p frost-rerandomized`

- Check if other crates are ready to be published: `for cs in ristretto255 ed25519 secp256k1 secp256k1-tr p256 ed448; do cargo publish -p frost-$cs --dry-run; done`. Fix any issues if needed.

    - If you get an error like this:

       “error: failed to verify package tarball Caused by: failed to select a version for the requirement `frost-core = "^0.3.0"` candidate versions found which didn't match: 0.2.0, 0.1.0 location searched: crates.io index required by package `frost-ed25519 v0.3.0 (frost/target/package/frost-ed25519-0.3.0)`”

       This is because the ciphersuite crates aren’t pointing at the new frost-core package. This is because you need to publish frost-core before you can publish the others otherwise they will not have the expected version to point to.

- Draft and publish releases for each of those crates:

    - Run `for cs in ristretto255 ed25519 secp256k1 secp256k1-tr p256 ed448; do gh release create "frost-$cs/v2.1.0" -n '' -t "frost-$cs v2.1.0" --latest=false; done` (replace both instances of the version)

- Publish those crates: `for cs in ristretto255 ed25519 secp256k1 secp256k1-tr p256 ed448; do cargo publish -p frost-$cs; done`


## Confirm

- Check versions in the crates to confirm everything worked:

    - [Frost core](https://crates.io/crates/frost-core/versions)
    - [Frost ed25519](https://crates.io/crates/frost-ed25519/versions)
    - [Frost ed448](https://crates.io/crates/frost-ed448/versions)
    - [Frost p256](https://crates.io/crates/frost-p256/versions)
    - [Frost ristretto255](https://crates.io/crates/frost-ristretto255/versions)
    - [Frost secp256k1](https://crates.io/crates/frost-secp256k1/versions)
    - [Frost secp256k1 tr](https://crates.io/crates/frost-secp256k1-tr/versions)
    - [Frost rerandomized](https://crates.io/crates/frost-rerandomized/versions)

- Let the team know in the #frost slack channel that the release is complete and successful


## In the case of an unsuccessful release

If something was wrongly tagged, you can just retag it.
If something was wrongly pushed to crates.io, you will need to make a new fixed
release and yank the wrong release.


