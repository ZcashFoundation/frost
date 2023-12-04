# Release Checklist


## One-time crates.io setup

1. Follow the steps in <https://doc.rust-lang.org/cargo/reference/publishing.html#before-your-first-publish> (you can create a token scoped to `publish-update`).
2. To get permissions to publish you’ll need to be in the [owners](https://github.com/orgs/ZcashFoundation/teams/owners) group. If you aren’t in there, ask someone in that group to add you


## Communication

3. Post in #frost slack channel and tag the Frost team that you’re going to be doing a release to freeze PR approvals until it’s done. E.g “@frost-core I’m doing a release of \<version> of Frost. Please do not merge any more PRs until I’m finished. Thanks.”


## Checks

4. Check current version for each crate. This is in the Cargo.toml file for frost-core, frost-ed448 etc.

   1. [Frost core version number](https://github.com/ZcashFoundation/frost/blob/main/frost-core/Cargo.toml#L7)
   2. [Frost ed25519 version number](https://github.com/ZcashFoundation/frost/blob/main/frost-ed25519/Cargo.toml#L8)
   3. [Frost ed448 version number](https://github.com/ZcashFoundation/frost/blob/main/frost-ed448/Cargo.toml#L7)
   4. [Frost p256 version number](https://github.com/ZcashFoundation/frost/blob/main/frost-p256/Cargo.toml#L8)
   5. [Frost re randomized version number](https://github.com/ZcashFoundation/frost/blob/main/frost-rerandomized/Cargo.toml#L8)
   6. [Frost ristretto255 version number](https://github.com/ZcashFoundation/frost/blob/main/frost-ristretto255/Cargo.toml#L8)
   7. [Frost secp256k1 version number](https://github.com/ZcashFoundation/frost/blob/main/frost-secp256k1/Cargo.toml#L7)

5. Decide which version to tag the release with (e.g. v0.3.0). Currently we always use the same release number for all crates, but it's possible for them to get out of sync in the future.

6. Create new issue. E.g. [Release v0.4.0](https://github.com/ZcashFoundation/frost/issues/377)


## Make changes

7. Bump the version of each crate in their Cargo.toml files

8. Bump the version used in the tutorial (importing.md)

9. Check if the [changelog](https://github.com/ZcashFoundation/frost/blob/main/frost-core/CHANGELOG.md) is up to date and update if required (we’re only keeping the one in frost-core for now). Double check using [FROST releases](https://github.com/ZcashFoundation/frost/releases) which will have a list of all the PRs that have been closed since the last release. Things to include in the changelog will be anything that impacts production code and big documentation changes. I.e. script and test changes should not be included. NOTE: Please add to the changelog whenever you make changes to the library as this will make things simpler for the person in charge of the release.

   1. Move version in changelog to Released
   2. Create a new version in “unreleased” in changelog

10. Update the version number for frost-core and frost-rerandomized in the Ciphersuite crates, e.g. in `frost-core = { path = "../frost-core", version = "0.4.0", features = ["test-impl"] }`. You'll need to do this for dependencies and dev-dependencies

11. Create a PR with subject `Release \<version number>` containing all these changes

12. You’ll need someone to review and approve it

13. Wait for it to pass CI checks


## Publish

14. Checkout main branch, **in the commit of the previously merged PR** (in case other stuff got merged after that)

15. Run `cargo publish -p frost-core --dry-run` to check if it’s ready to publish. Fix issues if any.

16. [Draft and publish a new release](https://github.com/ZcashFoundation/frost/releases/new) for frost-core.

    1. In “Choose a tag” type `<crate>/<version>` e.g. “frost-core/v0.2.0” and click “Create new tag”
    2. In “Target” select “main” as long as other PRs haven’t been merged after the version bump PR. Otherwise, **select the commit matching the PR that was merged above**.
    3. In “Release title” use `<crate> <version>` e.g. “frost-core v0.2.0”
    4. Paste the (raw Markdown) changelog for this version into the description box.
    5. Leave “Set as pre-release” **unchecked** (we should have checked it in earlier versions but the ship has sailed. It doesn’t matter much)
    6. **Check** “Set as the latest release”

17. Publish it with `cargo publish -p frost-core`

18. Check if frost-rerandomized is ready to be published: `cargo publish -p frost-rerandomized --dry-run`. Fix any errors if needed.

19. Draft and publish a frost-rerandomized release

    1. Use the same process as described for frost-core above, but you can leave the changelog empty and **uncheck** “Set as the latest release”

20. Publish it with `cargo publish -p frost-rerandomized`

21. Check if other crates are ready to be published: `for cs in ristretto255 ed25519 secp256k1 p256 ed448; do cargo publish -p frost-$cs --dry-run; done`. Fix any issues if needed.

    1. If you get an error like this:

       “error: failed to verify package tarball Caused by: failed to select a version for the requirement `frost-core = "^0.3.0"` candidate versions found which didn't match: 0.2.0, 0.1.0 location searched: crates.io index required by package `frost-ed25519 v0.3.0 (frost/target/package/frost-ed25519-0.3.0)`”

       This is because the ciphersuite crates aren’t pointing at the new frost-core package. This is because you need to publish frost-core before you can publish the others otherwise they will not have the expected version to point to.

22. Draft and publish releases for each of those crates (sorry, that will be boring)

    1. Use the same process as described for frost-core above (actions 1 - 3), but you can leave the changelog empty and **uncheck** “Set as the latest release”

23. Publish those crates: `for cs in ristretto255 ed25519 secp256k1 p256 ed448; do cargo publish -p frost-$cs; done`


## Confirm

24. Check versions in the crates to confirm everything worked: 

    1. [Frost core](https://crates.io/crates/frost-core/versions)
    2. [Frost ed25519](https://crates.io/crates/frost-ed25519/versions)
    3. [Frost ed448](https://crates.io/crates/frost-ed448/versions)
    4. [Frost p256](https://crates.io/crates/frost-p256/versions)
    5. [Frost ristretto255](https://crates.io/crates/frost-ristretto255/versions)
    6. [Frost secp256k1](https://crates.io/crates/frost-secp256k1/versions)
    7. [Frost rerandomized](https://crates.io/crates/frost-rerandomized/versions)

25. Let the team know in the #frost slack channel that the release is complete and successful


## In the case of an unsuccessful release

If something was wrongly tagged, you can just retag it.
If something was wrongly pushed to crates.io, you will need to make a new fixed
release and yank the wrong release.


