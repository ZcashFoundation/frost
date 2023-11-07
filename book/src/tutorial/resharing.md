# Key Resharing

_Resharing_ is the process of dynamically re-generating the shares of a FROST signing group, without recovering the group's master private key. This is effectively like repeating [the Distributed Key Generation process](./dkg.html) so that new shares are distributed to each signer, except the group **retains the same group verifying key.** Signers can verify their new shares are valid for the same group verifying key, and any invalid contributions can be identified just like during a FROST signing session.

In so doing, signing groups can achieve a number of interesting use cases:

- [Revoking exposed shares](#revoking-exposed-shares)
- Protection against [Mobile Adversaries](#mobile-adversaries)
- [Changing the signing group and threshold](#changing-the-group-and-threshold)

## Revoking Exposed Shares

Consider a case where one FROST signer's share was accidentally exposed publicly - For example, published on social media, or revealed through secret nonce reuse. The group's signing/security threshold will have decreased by one share (since the exposed share is known to everyone). The signing group would probably want some way to revoke that share, and optionally issue a new share to the signer who exposed their share, thereby recovering their group's desired security properties.

_Resharing_ provides a simple mechanism which accomplishes this. Every time the resharing protocol is executed, the signers overwrite their old signing shares with new shares which are _incompatible_ with their old ones. Assuming the other signers' shares remained secret until they were erased, the exposed share is now unusable.

### Example

Consider a 3-of-4 threshold signing group: Alice, Bob, Carol, and Dave, with shares `a1`, `b1`, `c1`, and `d1` respectively.

```
┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐
│    Alice   │  │    Bob     │  │   Carol    │  │    Dave    │
│ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────┐ │
│ │share_a1│ │  │ │share_b1│ │  │ │share_c1│ │  │ │share_d1│ │
│ └────────┘ │  │ └────────┘ │  │ └────────┘ │  │ └────────┘ │
└────────────┘  └────────────┘  └────────────┘  └────────────┘
```

Bob exposes his share `b1` by posting it to his MySpace page. How silly of Bob. Now his share `b1` is known by every other signer, and by the rest of the internet at large.

```
┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐
│    Alice   │  │    Bob     │  │   Carol    │  │    Dave    │
│ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────┐ │
│ │share_a1│ │  │ │share_b1│ │  │ │share_c1│ │  │ │share_d1│ │
│ └────────┘ │  │ └────────┘ │  │ └────────┘ │  │ └────────┘ │
└────────────┘  └────────────┘  └────────────┘  └────────────┘

           ┌──────────────────────────────────────┐
           │           Public Knowledge           │
           │             ┌────────┐               │
           │             │share_b1│               │
           │             └────────┘               │
           └──────────────────────────────────────┘
```

The signers agree to execute a resharing procedure, and issue Bob a new share in the process. Since Bob's `b1` share is public now, only a minimum of 2 out of the 4 signers need to be online and available to execute the resharing, but for practical reasons, it is best for all signers to participate.

This process results in four new shares, `a2`, `b2`, `c2`, and `d2` distributed to Alice, Bob, Carol and Dave respectively. These shares are **incompatible** with the four original shares `[a1, b1, c1, d1]`. Shares from different key-generation or resharing runs **cannot** be used together. For instance, the set of shares `[a2, b1, c2]` would **not** be sufficient to sign on behalf of the FROST group.

Upon receiving their new shares and acknowledging their validity, signers securely erase the old shares. This step is important but unfortunately not verifiable. Nothing prevents signers from keeping their old shares. If everyone behaves honestly though, the exposed share `b1` is rendered useless, because the other three shares `a1`, `c1`, and `d1` are now permanently erased and unknowable.

```
┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐
│    Alice   │  │    Bob     │  │   Carol    │  │    Dave    │
│ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────┐ │
│ │xxxxxxxx│ │  │ │xxxxxxxx│ │  │ │xxxxxxxx│ │  │ │xxxxxxxx│ │
│ └────────┘ │  │ └────────┘ │  │ └────────┘ │  │ └────────┘ │
│ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────┐ │
│ │share_a2│ │  │ │share_b2│ │  │ │share_c2│ │  │ │share_d2│ │
│ └────────┘ │  │ └────────┘ │  │ └────────┘ │  │ └────────┘ │
└────────────┘  └────────────┘  └────────────┘  └────────────┘

           ┌──────────────────────────────────────┐
           │           Public Knowledge           │
           │             ┌────────┐               │
           │             │share_b1│ <--- useless  │
           │             └────────┘               │
           └──────────────────────────────────────┘
```

## Mobile Adversaries

A _mobile adversary_ is a hypothetical term denoting an attacker who _corrupts_ some fraction of signers _slowly over time,_ such as by infecting their computers with a virus which only spreads to one signer at a time. However, a corrupted signer is not guaranteed to _stay_ corrupted. They might realize their system is infected and change over to a new computer, or they might reinstall their operating system.

As time goes on, the mobile adversary can _corrupt_ more of the signing group. Although some signers might _un-corrupt_ themselves, the adversary has still learned their secret share through the virus, and thus inches closer to breaking the security threshold `t` of the signing group. Once the adversary has corrupted `t` signers at least once, they have learned enough shares to sign arbitrary messages on behalf of the group.

_Resharing_ allows a signing group to defend themselves against mobile adversaries. By resharing on a regular basis, the group ensures any shares exposed to mobile adversaries are revoked. The adversary must then corrupt `t` or more signers _all at once,_ which is much harder. Provided the group executes the resharing protocol frequently enough, and signers overwrite their old signing shares each time, the mobile adversary will have a much harder time learning enough compatible shares to effectively attack the group.

## Changing the Group and Threshold

The recipients of shares from a resharing execution do not necessarily need to be the same as the original group of signers. It is possible for resharing to be used to intentionally exclude certain members of the signing group by effectively revoking their shares.

Equally, resharing can be used to add new signers into the group. Although if the group only wants to _add_ new members without removing any old signers, then using _repairable secret sharing_ is probably a simpler approach.

Perhaps most interestingly though, resharing allows the participants to decide on a new _group signing threshold_ which applies to the newly issued shares. Threshold modification has some gotchas though. The new threshold, denoted `t'`, only applies to the shares issued by the relevant resharing execution. The old shares from before the resharing are still valid and retain the old threshold, denoted `t`. Unless deleted, they could still be used together.

Thus, using resharing to modify the threshold should be used cautiously, and with the assumption that signers _could_ choose to retain their old shares. Reducing `t` is generally less problematic than increasing it, because new shares with a lower threshold will carry more signing power than old shares, and so signers have less incentive to retain the old shares.

# A Resharing Run

Resharing is split into three logical steps:

1. Broadcast commitment
2. Send subshares
3. Reconstruct new share
4. (optional) ACK and delete old share

## Broadcast Commitment

A public commitment must be sent over a [**broadcast channel**](/terminology.html#broadcast-channel) to all the recipient peers, who will be part of the new group after resharing.

## Send Subshares

Subshares, which one could think of as "shares-of-a-share", are sent to the recipients over [an authenticated & confidential channel](/terminology.html#peer-to-peer-channel).

## Reconstruct New Share

The recipients receive commitments and subshares from the resharers. They can verify each subshare is consistent with its sender's commitment, and also compute a new signing share from the subshares.

If the recipient knows the public verifying key of the group they are joining, the recipient can verify the resulting share they reconstructed is valid for that group key.

If the recipient knows the public verifying _shares_ of the individual resharers, they can assign blame to any resharer who may have provided them with an invalid subshare and commitment pair.

## (optional) ACK and Delete Old Share

Once all recipients have acknowledged they received and reconstructed a new set of valid signing shares, then the resharers can erase their old signing shares.

```admonish danger
It is important that all recipients acknowledge successful resharing before any signing shares are erased. Premature share erasure can result in a ['Forget-and-Forgive'](https://iacr.org/submit/files/slides/2021/rwc/rwc2021/31/slides.pdf) attack, where a single malicious signer can convince some of the group to overwrite their old shares by giving providing valid subshares, but block others from finishing the procedure by providing them with _invalid_ subshares.

This attack _splits_ the group in two: Those who have _new_ shares and those who have _old_ shares. If `t > n/2` (i.e. if the threshold is greater than half the group size), this results in a deadlock where not enough compatible signing shares exist anymore for the group to recover.
```
