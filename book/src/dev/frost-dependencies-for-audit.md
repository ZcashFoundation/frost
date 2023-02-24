# FROST dependencies

This is a list of production Rust code that is in scope and out of scope for FROSTs second audit.

--
## Full Audit 

### FROST Crates

| Name | Version | Notes
|------| ------- | -----
| frost-core | v0.1.0 |
| frost-ed25519 | v0.1.0 |
| frost-ed448 | v0.1.0 |
| frost-p256 | v0.1.0 |
| frost-rerandomized | v0.1.0 | Out of scope
| frost-ristretto255 | v0.1.0 |
| frost-secp256k1 | v0.1.0 |

--
## Partial Audit



---
## Out of Scope

The following list of dependencies is out of scope for the audit.

### `frost-core` Dependencies

| Name | Version | Reason | Notes
|------| ------- | -----  | -----
| byteorder | v1.4.3 | |
| criterion | v0.4.0 | |
| debugless-unwrap | v0.0.4 | |
| digest | v0.10.6 | |
| hex | v0.4.3 | |
| proptest | v1.1.0 | |
| proptest-derive | v0.3.0 | |
| rand_core | v0.6.4 | |
| serde_json | v1.0.93 | |
| thiserror | v1.0.38 | |
| visibility | v0.0.1 | |
| zeroize | v1.5.7 | |

### `frost-ed25519` Dependencies

| Name | Version | Reason | Notes
|------| ------- | -----  | -----
| curve25519-dalek | v4.0.0-pre.1 | |
| rand_core | v0.6.4 | |
| sha2 | v0.10.6 | |

### `frost-ed448` Dependencies

| Name | Version | Reason | Notes
|------| ------- | -----  | -----
| ed448-goldilocks | v0.4.0 | |
| rand_core | v0.6.4 | |
| sha3 | v0.10.6 | |

### `frost-p256` Dependencies

| Name | Version | Reason | Notes
|------| ------- | -----  | -----
| p256 | v0.11.1 | |
| rand_core | v0.6.4 | |
| sha2 | v0.10.6 | |

### `frost-rerandomized` Dependencies

| Name | Version | Reason | Notes
|------| ------- | -----  | -----
| rand_core | v0.6.4 | |

### `frost-ristretto255` Dependencies

_None_

### `frost-secp256k1` Dependencies

| Name | Version | Reason | Notes
|------| ------- | -----  | -----
| k256 | v0.12.0-pre.0 | |
| rand_core | v0.6.4 | |
| sha2 | v0.10.6 | |