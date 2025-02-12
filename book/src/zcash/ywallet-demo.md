# Ywallet Demo Tutorial

This tutorial explaining how to run the FROST demo using Ywallet that was
[presented during Zcon4](https://www.youtube.com/watch?v=xvzESdDtczo) (though it
has been updated and it differs from what was presented).

Ywallet supports [offline
signing](https://ywallet.app/advanced/offline_signature/), which allows having a
view-only account that can generate a transaction plan, which can be signed by
an offline wallet also running Ywallet. The demo uses this mechanism but signs
the transaction plan with a command line tool, using FROST.

This tutorial assumes familiarity with the command line.


## Setting up

Install `cargo` and `git`.

[Install Ywallet](https://ywallet.app/installation/).

Install the `frost-client` tool:

```
cargo install --git https://github.com/ZcashFoundation/frost-zcash-demo.git --locked frost-client
```

Install the `zcash-sign` tool:

```
cargo install --git https://github.com/ZcashFoundation/frost-zcash-demo.git --locked zcash-sign
```

Switch to an empty folder which will store the files generate in the demo.
For example:

```
mkdir frost-demo
cd frost-demo/
```


### Running the server

This demo uses the ZF FROST server (frostd) to help participants communicate.
While in practice users would use an existing online server, for the demo you
can run a local server by following [these instructions](./server.md) (the
"Compiling, Running and Deploying" and "Local Testing" sections).

The rest of the tutorial assumes the server is up and running.


### Initializing the users

Run the following command to initialize three users (in practice, each user
would run a similar command, but for demo purposes we're assuming
you will simulate all of them in the same machine, so run these
commands in your machine):

```
frost-client init -c alice.toml
frost-client init -c bob.toml
frost-client init -c eve.toml
```

This will create a config file for three users; Alice, Bob and Eve.

```admonish note
If you really want to run the demo in separate machines, then you can omit the
`-c alice.toml` part of the command (i.e. run `frost-client init`); it will
save to a default location in the user's home directory.
```


## Generating FROST key shares

First we will generate the FROST key shares. For simplicity we'll use trusted
dealer; if you want to use Distributed Key Generation, skip to the next section.

In a new terminal (in case the previous terminal is running the server), run the
following:

```
frost-client trusted-dealer -d "Alice, Bob and Eve's group" --names Alice,Bob,Eve -c alice.toml -c bob.toml -c eve.toml -C redpallas
```

This will by default generate a 2-of-3 key shares. The key shares will be
written into each participant's config file.  You can change the threhsold,
number of shares and file names using the command line; append `-h` to the
commend above for the command line help.


## Generating FROST key shares using DKG

For real-word usage we commend generating key shares using Distributed Key
Generation. If you did the previous section, skip to "Generating the Full
Viewing Key for the wallet".


```admonish note
This section assumes each participant is running the commands in their own
machine. If you want to simulate all of them in a single machine,
specify the config file for the user (e.g. `-c alice.toml`) accordingly.
```


### Initializing config files

If they haven't yet, each participant should run:

```
frost-client init
```


### Sharing contacts

Each participant must now generate a contact string that they will need to share
with the other participants. This contact string will include a name, which they
can choose when exporting and will be shown to whoever they send the contact to.

Run the following, substituting the name accordingly:

```
frost-client export --name 'Alice'
```

The command will print an encoded contact string such as
`zffrost1qyqq2stvd93k2g84hudcr98zp67a9rnx9v00euw9e5424hjathvre7ymy344fynjdvxmwxfg`.
Send it to the other participants using some trusted communication channel
(instant messaging, etc.).

The other participants will send you their contacts. Import them by running the
following command for each contact (replace `<contact-string>` with the contact
string accordingly):

```
frost-client import <contact-string>
```


### Generating shares

Finally, to generate the shares, one of the participants will need to initiate
the process. They will need to public key of each participant, so they need to
first list them with the following command:

```
frost-client contacts
```

Then run the following command, replacing the `<pubkey1>` and `<pubkey2>` hex
strings with the public keys of the contacts which will participate (along with
the user running the command):

```
frost-client dkg -d 'Alice, Bob and Eve's group' -s localhost:2744 -S <pubkey1>,<pubkey2> -t 2 -C redpallas -c alice.toml
```

The user should then notify the others that a signing session has started (e.g.
via instant messaging again), and also share the threshold number that was used.
They should then run the following, replacing the name of the group if they wish
and the threshold number with the one given by the first participant.

```
frost-client dkg -d 'Alice, Bob and Eve's group' -s localhost:2744 -t 2 -C redpallas
```

```admonish note
A future version might not require specifying the threshold and group name.
```


## Generating the Full Viewing Key for the wallet

Next, we will need to generate a Zcash Full Viewing Key from the FROST group
material we have just generated; this address will then be imported into a wallet
so that we'll be able to create Zcash transactions for it.

Run the following command:

```
frost-client groups
```

It will list all groups you're in - at this point it should list the only one
you have just created. Copy the Public Key it shows (it will look like e.g.
`79d6bcee79c88ad9ba259067772b97f5de12f1435b474d03bc98f255be08a610`)

The run the following command, replacing `<ak>` with the value you copied.

```
zcash-sign generate --ak <ak> --danger-dummy-sapling
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

```admonish danger
The address being show by Ywallet is a unified address that includes both an
Orchard and Sapling address. For the demo to work, you need to receive funds in
your Orchard address. Whether that will happen depends on multiple factors so
it's probably easier to use just the Orchard-only address printed by the signer.
In Ywallet, you can also swipe right on the QR Code until it shows the "Orchard
Address". **IF YOU SEND IT TO THE SAPLING ADDRESS, THE FUNDS WILL BECOME
UNSPENDABLE AND WILL BE LOST!**
```


## Creating the transaction

Now you will create the transaction that you wish to sign with FROST. Click
the arrow button and paste the destination address (send it to yourself if
you don't know where to send it). Type the amount you want to send and
click the arrow button.

The wallet will show the transaction plan. Click the snowflake button. It will
show a QR code, but we want that information as a file, so click the floppy disk
button and save the file somewhere (e.g. `tx-plan.json`).


## Signing the transaction

Now you will need to simulate two participants and a Coordinator to sign the
transaction, and you should still have the FROST server running which will
handle communications between them. It's probably easier to open three new
terminals.

Go back to the signer terminal and run the following, replacing `<tx_plan_path>`
with the path to the file you saved in the previous step, `<ufvk>` with the UFVK
hex string printed previously, and `<tx_signed_path>` with the path where you
want to write the signed transaction (e.g. `tx-signed.raw`).

```
zcash-sign sign --tx-plan <tx_plan_path> --ufvk <ufvk> -o <tx_signed_path>
```

The program will print a SIGHASH and a Randomizer, and will prompt for a
signature. This is what you will get after running FROST, so let's do that;
leave the prompt there without typing anything.


### Coordinator

In the second terminal, the Coordinator, run (in the same folder where you
initialized the users and ran the key generation) the following:

```
frost-client groups -c alice.toml
```

This will list the groups Alice is in; it should only list the one you created
earlier. You will need to copy some values in the command. Run the following,
replacing the value after `<group>` with the "Public key" listed for the group;
replacing `<pubkey1>` and `<pubkey2>` with the public keys of Alice and Bob (the
hexadecimal values printed next to their names; Alice's name will be empty to
indicate it's her own).

```
frost-client coordinator -c alice.toml --server-url localhost:2744 --group <group> -S <pubkey1>,<pubkey2> -m - -r -
```

It will prompt you for a message. Paste the SIGHASH generated with the
`zcash-sign` tool and press enter. It will then prompt for a randomizer. Paste
the one generated with the `zcash-sign` tool and press enter.

The tool will connect to the server and wait for the other participants.

```admonish warning
If you prefer to pass the message (SIGHASH) or randomizer as files by using
the `-m` and `-r` arguments, you will need to convert them to binary format.
```


### Participant 1 (Alice)

In the third terminal, Participant 1, run the following (replacing `<group>`
with the same group public key used in the previous command):

```
frost-client participant -c alice.toml --server-url localhost:2744 --group <group>
```

(We are using "Alice" again. There's nothing stopping a Coordinator from being a
Partcipant too!)


### Participant 2 (Bob)

In the fourth terminal, for Participant 2, run the following (replacing `<group>`
again):

```
frost-client participant -c bob.toml --server-url localhost:2744 --group <group>
```


### Coordinator

Go back to the Coordinator CLI. The protocol should run and complete
successfully. It will print the final FROST-generated signature. Hurrah! Copy it
(just the hex value).

Go back to the signer and paste the signature. It will write the raw signed
transaction to the file you specified.


## Broadcasting the transaction

Go back to Ywallet and return to its main screen. In the menu, select "More" and
"Broadcast". Click the upper-right box-with-an-arrow icon and select the raw
signed transaction file you have just generated (`tx-signed.raw` if you followed
the suggestion).

That's it! You just sent a FROST-signed Zcash transaction.
