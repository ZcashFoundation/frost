# Refreshing Shares using a Trusted Dealer

The diagram below shows the refresh share process. Dashed lines
represent data being sent through an [authenticated and confidential communication
channel](https://frost.zfnd.org/terminology.html#peer-to-peer-channel).

<!-- ![Diagram of Refreshing shares, illustrating what is explained in the text](refreshing.png) -->

The Trusted Dealer needs to first run `compute_refreshing_shares` where the new SecretShares are generated and then verified.
This is done with
[`KeyPackage::try_from()`](https://docs.rs/frost-core/latest/frost_core/frost/keys/struct.KeyPackage.html#method.try_from):
`caluclate_zero_key` returns a new SecretShare and PublicKeyPackage
Each new `SecretShare` and `PublicKeyPackage` must then be sent via an [**authenticated** and
**confidential** channel
](https://frost.zfnd.org/terminology.html#peer-to-peer-channel) for each
participant, who must verify the package to obtain a `KeyPackage` which contains
their signing share, verifying share and group verifying key. 

Each Participant then runs `refresh_share` to generate a new `KeyPackage`.

```admonish danger
The refreshed `KeyPackage` contents must be stored securely and the original 
`KeyPackage` should be deleted. For example:

- Make sure other users in the system can't read it;
- If possible, use the OS secure storage such that the package
  contents can only be opened with the user's password or biometrics.
```
