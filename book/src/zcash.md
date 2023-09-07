# FROST with Zcash

FROST can be used with the [Zcash](https://z.cash/) cryptocurrency, allowing
the creation of a wallet shared between multiple participants where multiple
participants must authorize a transaction before it can go through.

In a regular Zcash wallet, the spending key (commonly derived from a seed
phrase) allows freely spending from the wallet. If the key is lost or gets
hacked, then the wallet owner will lose access to their funds forever.

With FROST, only shares of the related spend authorization key will exist, between multiple 
participants. During wallet creation, a threshold is set, and only that number of
participants (or more) can jointly create a transaction that spends funds from the wallet.

Some possible applications are:

- Creating a wallet that is shared between members of a organization that
  manages certain funds. For example, a 3-of-5 wallet can be created which
  will require 3 members to authorize spending the funds.
- Shared custody services can be created so that users can have their own wallet
  and can spend their funds with the help of the service, and will not lose
  access to the funds in case they lose the device with their key share. For
  example, a 2-of-3 wallet where the user keeps one share, the service keeps
  another, and the third share is backed up in the user's cloud.

FROST thus helps addressing one of the biggest challenges in cryptocurrencies,
which is the protecting the wallet key from either being accidentally lost or
being hacked. Before, users needed to choose to either manage their own funds
will puts a huge amount of responsibility on them and is well known to work
greatly in practice, or to leave their funds to be managed by some custody
service which is also known to be a risk. With FROST, users can share the
responsibility between multiple entities or persons (or even multiple devices
they own).

This section describes in more details how FROST can be used with Zcash.

