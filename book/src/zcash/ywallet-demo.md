# Ywallet Demo Tutorial

This tutorial explaining how to run the FROST demo using Ywallet that was
[presented during Zcon4](https://www.youtube.com/watch?v=xvzESdDtczo).

Ywallet supports [offline
signing](https://ywallet.app/advanced/offline_signature/), which allows having a
view-only account that can generate a transaction plan, which can be signed by
a offline wallet also running Ywallet. The demo uses this mechanism but signs
the transaction plan with a command line tool, using FROST.

This tutorial assumes familiarity with the command line.

## Setting up

Install `cargo` and `git`.

[Install Ywallet](https://ywallet.app/installation/).

Clone the repository:

```
git clone https://github.com/ZcashFoundation/frost-zcash-demo.git
```

## Generating FROST key shares

First we will generate the FROST key shares. For simplicity we'll use trusted
dealer, DKG will be described later.

Run the following (it will take a bit to compile):

```
cd frost-zcash-demo/
cargo run --bin trusted-dealer -- -C redpallas
```

This will by default generate a 2-of-3 key shares. The public key package
will be written to `public-key-package.json`, while key packages will be
written to `key-package-1.json` through `-3`. You can change the threshold,
number of shares and file names using the command line; append `-- -h`
to the command above for the command line help.

```admonish info
If you want to use DKG instead of Trusted Dealer, instead of the command above,
 run this for each participant, in separate terminals for each:

`cargo run --bin dkg -- -C redpallas`

and follow the instructions. (There will be a considerable amount of
copy&pasting!)
```

## Generating the Full Viewing Key for the wallet

Get the `verifying_key` value that is listed inside the Public Key Package in
`public-key-package.json`. For example, in the following package

```
{"verifying_shares": ...snip... ,"verifying_key":"d2bf40ca860fb97e9d6d15d7d25e4f17d2e8ba5dd7069188cbf30b023910a71b","ciphersuite":"FROST(Pallas, BLAKE2b-512)"}
```

you would need to copy
`d2bf40ca860fb97e9d6d15d7d25e4f17d2e8ba5dd7069188cbf30b023910a71b`.

The run the following command, replacing `<ak>` with the value you copied.

```
cd zcash-sign/
cargo run --release -- generate --ak <ak> --danger-dummy-sapling
```

It will print an Orchard address, and a Unified Full Viewing Key. Copy and
paste both somewhere to use them later.

## Importing the Full Viewing Key into Ywallet

Open Ywallet and click "New account". Check "Restore an account" and
paste the Unified Full Viewing Key created in the previous step. Click
"Import".

## Funding the wallet

Now you will need to fund this wallet with some ZEC. Use the Orchard address
printed by the signer (see warning below). Send ZEC to that address using
another account (or try [ZecFaucet](https://zecfaucet.com/)).

```admonish warning
The address being show by Ywallet is a unified address that includes both an
Orchard and Sapling address. For the demo to work, you need to receive funds in
you Orchard address. Whether that will happen depends on multiple factors so
it's probably easier to use just the Orchard-only address printed by the signer.
**If you send it to the Sapling address, the funds will be unspendable and lost!**
```

## Creating the transaction

Now you will create the transaction that you wish to sign with FROST. Click
the arrow button and paste the destination address (send it to yourself if
you don't know where to send it). Type the amount you want to send and
click the arrow button.

The wallet will show the transaction plan. Click the snowflake button. It will
show a QR code, but we want that information as a file, so click the floppy disk
button and save the file somewhere (e.g. `tx.raw` as suggested by Ywallet).

## Signing the transaction

Go back to the signer terminal and run the following, replacing `<tx_plan_path>`
with the path to the file you saved in the previous step, `<ufvk>` with the UFVK
hex string printed previously, and `<tx_signed_path>` with the path where you
want to write the signed transaction (e.g. `tx-signed.raw`).

```
cargo run --release -- sign --tx-plan <tx_plan_path> --ufvk <ufvk> -o <tx_signed_path>
```

The program will print a SIGHASH and a Randomizer.


### Running the server

Now you will need to simulate two participants and a Coordinator to sign the
transaction, and the FROST server that handles communications between them.
It's probably easier to open four terminals.

In the first one, the server, run (in the same folder where key generation was
run):

```
RUST_LOG=debug cargo run --bin server
```

### Registering users

In order to interact with the server, you will need to register users. For this
guide we will need two. In a new terminal, run the following command for user
"alice" (replace the password if you want):

```
curl --data-binary '{"username": "alice", "password": "foobar10", "pubkey": ""}' -H 'Content-Type: application/json' http://127.0.0.1:2744/register
```

It will output "null". (The "pubkey" parameter is not used currently and should
be empty.) Also register user "bob":

```
curl --data-binary '{"username": "bob", "password": "foobar10", "pubkey": ""}' -H 'Content-Type: application/json' http://127.0.0.1:2744/register
```

You only need to do this once, even if you want to sign more than one
transaction. If for some reason you want to start over, close the server and
delete the `db.sqlite` file.

Feel free to close this terminal, or reuse it for the next step.

```admonish warning
Do not use passwords that you use in practice; use dummy ones instead. (You
shouldn't reuse passwords anyway!) For real world usage you would need to take
more care to not end up writing the password to your shell history. (In real
world usage we'd expect this to be done by applications anyway.)
```

### Coordinator

In the second terminal, the Coordinator, run (in the same folder where key
generation was run):

```
export PW=foobar10
cargo run --bin coordinator -- -C redpallas --http -u alice -w PW -S alice,bob -r -
```

We will use "alice" as the Coordinator, so change the value next to `export PW=`
if you used another password when registering "alice".

And then:

- It should read the public key package from `public-key-package.json`.
- When prompted for the message to be signed, paste the SIGHASH printed by the
  signer above (just the hex value, e.g.
  ``4d065453cfa4cfb4f98dbc9cff60c4a3904ed91c523b8ef8d67d28bea7f12ea3``).
- When prompted for the randomizer, paste the randomizer printed by the signer
  above (again just the hex value)

```admonish warning
If you prefer to pass the randomizer as a file by using the `--randomizer`
argument, you will need to convert it to binary format.
```

### Participant 1 (alice)

In the third terminal, Participant 1, run the following:

```
export PW=foobar10
cargo run --bin participant -- -C redpallas --http --key-package key-package-1.json -u alice -w PW
```

(We are using "alice" again. There's nothing stopping a Coordinator from being a
Participant too!)

### Participant 2 (bob)

In the fourth terminal, for Participant 2, run the following:

```
export PW=foobar10
cargo run --bin participant -- -C redpallas --http --key-package key-package-2.json -u bob -w PW
```

### Coordinator

Go back to the Coordinator CLI. The protocol should run and complete
successfully. It will print the final FROST-generated signature. Hurrah! Copy it
(just the hex value).

Go back to the signer and paste the signature. It will write the raw signed
transaction to the file you specified.

## Broadcasting the transaction

Go back to Ywallet and return to its main screen. In the menu, select "Advanced"
and "Broadcast". Select the raw signed transaction file you have just generated
(`tx-signed.raw` if you followed the suggestion).

That's it! You just sent a FROST-signed Zcash transaction.
