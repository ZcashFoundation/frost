use lazy_static::lazy_static;
use serde_json::Value;

const RISTRETTO255_SHA512_JSON: &str = r#"
{
  "config": {
    "NUM_SIGNERS": "3",
    "THRESHOLD_LIMIT": "2",
    "name": "FROST(ristretto255, SHA512)",
    "group": "ristretto255",
    "hash": "SHA-512"
  },
  "inputs": {
    "group_secret_key": "ca8009d372fa61174ae16d422a216ff503eccfe12348a5a2e4b30e95fdd92909",
    "group_public_key": "6acc470751d8954bc4bf3581c3f0d25d4d65ef818318de89f9500d288d8dcf05",
    "message": "74657374",
    "signers": {
      "1": {
        "signer_share": "1767555c694baffbb51ed5e75e3c199f35d025a7a0b40124d93d6dc824cf240d"
      },
      "2": {
        "signer_share": "7779ab884539ea874bbf44eab45de43367b47b6c1d215ea5cdc7cbfb4bc41f01"
      },
      "3": {
        "signer_share": "c45ff7113c8a376cb7fcab8fe9788edd9898d1319a8dba26c2512a2f73b91a05"
      }
    }
  },
  "round_one_outputs": {
    "participants": [
      "1",
      "2"
    ],
    "commitment_list": "00013294581c296781c6fdb2696b2a8d08f961311e15b4bc3614daec6a19a78cd77a42a3cfa235deb33e7f99a21f4e22b7090d9c278f2613664dff607115cecedf58000208659fe4a31c1775caa4488f669324460b5d972df8983a6cf8e624f79906a639285fd985bb44d53b28b6523aa1c459a94bface28ab2f4fcdbc5215df5d9be234f226c1530c93fbfe1a29f34aa2e13da14ace01b6e6412e36d5e01baba2c78e4921dc1c0b7143210bb0fc42553c3a9490ba011e30250727c0189372a38632591f",
    "group_binding_factor": "190c206d7368cc7cdf8539680f45a82836889db034464d9f9cc13c970fc9d20e",
    "outputs": {
      "1": {
        "hiding_nonce": "7e119fcff436f4817fbcd1b09e82d7d2ff6dd433b0f81e012cadd4662282b809",
        "binding_nonce": "3b3bbe82babf2a67ded81b308ba45f73b88f6cf3f6aaa4442256b7a0a6a9e20c",
        "hiding_nonce_commitment": "3294581c296781c6fdb2696b2a8d08f961311e15b4bc3614daec6a19a78cd77a",
        "binding_nonce_commitment": "42a3cfa235deb33e7f99a21f4e22b7090d9c278f2613664dff607115cecedf58"
      },
      "2": {
        "hiding_nonce": "488cfde0a2bba98ba4c3e65645e1b77386eb4063e497801fbbbd112ad1f7d708",
        "binding_nonce": "f33b7cd25041000d7935823cb0c99503afac2860b1c099435eb472bb29329e02",
        "hiding_nonce_commitment": "08659fe4a31c1775caa4488f669324460b5d972df8983a6cf8e624f79906a639",
        "binding_nonce_commitment": "285fd985bb44d53b28b6523aa1c459a94bface28ab2f4fcdbc5215df5d9be234"
      }
    }
  },
  "round_two_outputs": {
    "participants": [
      "1",
      "2"
    ],
    "outputs": {
      "1": {
        "sig_share": "0f03834e01fc2447135f694a5d1d6493f7a21fcf6fc41191118000e8b9a29306",
        "group_commitment_share": "76818272e9bd5d71f062dce08687919850aaf4b8cfd135ad70e50e0267d87246"
      },
      "2": {
        "sig_share": "08442979523a3e335cf4c03fe58cdcec25841e64f5a4f2ac656730c1fee43509",
        "group_commitment_share": "62e97479cb0df12293aadfa88e5d1caa7f82d548f77eaa2408fe4bca61916439"
      }
    }
  },
  "final_output": {
    "sig": {
      "R": "56604a3b6ca135e56f5d68d2f6496e3e0e9b9ec691a3790f5e8311d24d75ce13",
      "z": "1747acc75336637a6f532a8a42aa40801d273e336569043e77e730a9b887c90f"
    }
  }
}
"#;

lazy_static! {
    pub static ref RISTRETTO255_SHA512: Value =
        serde_json::from_str(RISTRETTO255_SHA512_JSON).expect("Test vector is valid JSON");
}
