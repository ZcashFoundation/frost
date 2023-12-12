# Ywallet Demo Tutorial

This tutorial explaing how to run the FROST demo using Ywallet that was
[presented during Zcon4](https://www.youtube.com/watch?v=xvzESdDtczo).

## Information

1. The Trusted Dealer journey
2. RedPallas
3. YWallet
4. Sprout
5. [Sapling](https://docs.rs/reddsa/0.5.1/reddsa/sapling/index.html)
6. [frost-ed25519 crate](https://crates.io/crates/frost-ed25519)

Ywallet supports [offline
signing](https://ywallet.app/advanced/offline_signature/), which allows having a
view-only account that can generate a transaction plan, which can be signed by
a offline wallet also running Ywallet. The demo uses this mechanism but signs
the transaction plan with a command line tool, using FROST.

This tutorial assumes familiarity with the command line.

## Setting up

Install `cargo` and `git`.

[Install Ywallet](https://ywallet.app/installation/).

Clone the repositories:

```
git clone https://github.com/ZcashFoundation/frost-zcash-demo.git
git clone --recurse-submodules --branch frost-demo https://github.com/ZcashFoundation/zwallet.git
git clone https://github.com/ZcashFoundation/zcash.git
```

Download Sprout and Sapling parameters:


[Sprout params](https://download.z.cash/downloads/sprout-groth16.params)

[Sapling spend params](https://download.z.cash/downloads/sapling-spend.params)

[Sapling output params](https://download.z.cash/downloads/sapling-output.params)

Move the params files into `zwallet/native/zcash-params/src/`


## Generating FROST key shares

First we will generate the FROST key shares. For simplicity we'll use trusted
dealer, DKG will be described later.

Run the following (it will take a bit to compile):

```
cd frost-zcash-demo/
cargo run --bin trusted-dealer --features redpallas
```

Answer the prompts with `2` (minimum number of signers), `3`
(maximum) and empty, pressing enter to submit each.

A bunch of information will be printed. Copy and paste them somewhere to use
them later, or leave the terminal open.

```admonish info
If you want to use DKG instead of Trusted Dealer, instead of the command above,
 run this for each participant, in separate terminals for each:

`cargo run --bin dkg --features redpallas`

and follow the instructions. (There will be a considerable amount of
copy&pasting!)
```

## Generating the Full Viewing Key for the wallet

In a new terminal, switch to the folder of the signer tool:


```
cd zwallet/native/zcash-sync/
```

Before running it, you will need to create a seed phrase which is used to
generate the Sapling address. This wouldn't be needed since the demo only works
with an Orchard address, but due to current limitations in the underlying
crates, we also need to generate a Sapling address which won't be used in the
demo. Generate a fresh 24-word seed phrase, for example using [this
site](https://iancoleman.io/bip39/) (reminder: don't use random sites to
generate seed phrases unless for testing purposes!), then write to a file called
`.env` in the signer folder in the following format, putting the seed phrase
inside the quotes:

 ```
 KEY="seed phrase"
 ```

We can finally generate a new wallet. Run the following command; it will
take a bit to compile. It will show a bunch of warnings which is normal.

```
cargo run --release --bin sign --features dotenv -- -g
```

When prompted for the `ak`, paste the `verifying_key` value that was printed in
the previous part, inside the Public Key Package. For example, in the following
package

```
Public key package:
{"verifying_shares": ...snip... ,"verifying_key":"d2bf40ca860fb97e9d6d15d7d25e4f17d2e8ba5dd7069188cbf30b023910a71b","ciphersuite":"FROST(Pallas, BLAKE2b-512)"}
```

you would need to use
`d2bf40ca860fb97e9d6d15d7d25e4f17d2e8ba5dd7069188cbf30b023910a71b`. Press
enter to submit.

It will print an Orchard address, and a Unified Full Viewing Key. Copy and
paste both somewhere to use them later.

## Importing the Full Viewing Key into Ywallet

Open Ywallet and click "New account". Check "Restore an account" and
paste the Unified Full Viewing Key created in the previous step. Click
"Import".

In the "Rescan from..." window, pick today's date (since the wallet was just
created) and press OK. The wallet should open.

You will need to change some of Ywallet configurations. Click the three dots
at the top right and go to Settings. Switch to Advanced mode and click
OK. Go back to the Settings and uncheck "Use QR for offline signing".

## Funding the wallet

Now you will need to fund this wallet with some ZEC. Use the Orchard address
printed by the signer (see warning below). Send ZEC to that address using
another account (or try [ZecFaucet](https://zecfaucet.com/)). Wait until the
funds become spendable (this may take ~10 minutes). You can check if the funds
are spendable by clicking the arrow button and checking "Spendable Balance"

```admonish warning
The address being show by Ywallet is a unified address that includes both an Orchard and Sapling address. For the demo to work, you need to receive funds in you Orchard address. Whether that will happen depends on multiple factors so it's probably easier to use just the Orchard-only address printed by the signer.
```

## Creating the transaction

Now you will create the transaction that you wish to sign with FROST. Click
the arrow button and paste the destination address (send it to yourself if
you don't know where to send it). Type the amount you want to send and
click "Send".

The wallet will show the transaction plan. Click "Send". It won't actually
send - it will prompt you for where to save the transaction plan. Save it
somewhere.

## Signing the transaction

Go back to the signer terminal and run (adjust paths accordingly. The "tx.json"
input parameters must point to the file you save in the previous step, and the
"tx.raw" output parameter is where the signed transaction will be written).

```
cargo run --release --bin sign --features dotenv -- -t ~/Downloads/tx.json -o ~/Downloads/tx.raw
```

When prompted, paste the UFVK generated previously.

The program will print a SIGHASH and a Randomizer.

Now you will need to simulate two participants and a Coordinator to sign the
transaction. It's probably easier to open three terminals.

In the first one, the Coordinator, run (in the same folder where key
generation was run):

```
cargo run --bin coordinator --features redpallas
```

And then:

- Paste the JSON public key package generate during key generation (it's a single
  line with a JSON object).
- Type `2` for the number of participants.
- Paste the identifier of the first participant, you can see it in the Secret
  Share printed during key generation. If you used trusted dealer key
  generation, it will be
  `0100000000000000000000000000000000000000000000000000000000000000`.
- Paste the second identifier, e.g.
  `0200000000000000000000000000000000000000000000000000000000000000`.
- When prompted for the message to be signed, paste the SIGHASH printed by the
  signer above (just the hex value, e.g.
  ``4d065453cfa4cfb4f98dbc9cff60c4a3904ed91c523b8ef8d67d28bea7f12ea3``).

Create a new terminal, for participant 1, and run:

```
cargo run --bin participant --features redpallas
```

And then:

- Paste the Secret Share printed during key generation (or Key Package if you
  used DKG).
- Copy the SigningCommitments line and paste into the Coordinator CLI.

Do the same for participant 2.

You should be at the Coordinator CLI. Paste the Randomizer generated by the
signer before and copy the Signing Package line that it was printed by the
Coordinator CLI before the Randomizer prompt.

Switch to participant 1 and:

- Paste the Signing Package
- Paste the Randomizer printed by the signer before.
- Copy the SignatureShare line and paste it into the Coordinator CLI.

Do the same for participant 2.

You should be at the Coordinator CLI. It has just printed the final
FROST-generated signature. Hurrah! Copy it (just the hex value).

Go back to the signer and paste the signature. It will write the raw signed
transaction to the file you specified.

## Broadcasting the transaction

Go back to Ywallet and return to its main screen. In the menu, select "Advanced"
and "Broadcast". Select the raw signed transaction file you have just generated.

That's it! You just sent a FROST-signed Zcash transaction.
