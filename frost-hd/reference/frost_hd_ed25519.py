#!/usr/bin/env python3
"""Independent FROST-HD-v1 Ed25519 reference model.

Research-only code. It implements the normative transcript and group equations
without depending on the Rust prototype. It is not constant-time and must not
be used with production secrets.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

FIELD_P = 2**255 - 19
SCALAR_Q = 2**252 + 27742317777372353535851937790883648493
EDWARDS_D = (-121665 * pow(121666, FIELD_P - 2, FIELD_P)) % FIELD_P
SQRT_M1 = pow(2, (FIELD_P - 1) // 4, FIELD_P)
IDENTITY = (0, 1)

KEY_FAMILY_VERSION = 1
PATH_ENCODING_VERSION = 1
MAX_PATH_DEPTH = 64
MAX_EDGE_RETRIES = 2**16
CIPHERSUITE_ID = b"FROST-ED25519-SHA512-v1"
PROFILE_ID = b"FROST-HD-ED25519-SHA512-H1-v1"

DST_CONTEXT = b"FROST-HD-v1/context"
DST_EDGE = b"FROST-HD-v1/edge"
DST_TWEAK_PRF = b"FROST-HD-v1/tweak-prf"
DST_CHILD_KEY = b"FROST-HD-v1/child-derivation-key"
DST_HASH_TO_SCALAR = b"FROST-HD-v1/hash-to-scalar"


def _inverse(value: int) -> int:
    value %= FIELD_P
    if value == 0:
        raise ZeroDivisionError("cannot invert zero")
    return pow(value, FIELD_P - 2, FIELD_P)


def _recover_x(y: int, sign: int) -> int:
    numerator = (y * y - 1) % FIELD_P
    denominator = (EDWARDS_D * y * y + 1) % FIELD_P
    x_squared = numerator * _inverse(denominator) % FIELD_P
    x = pow(x_squared, (FIELD_P + 3) // 8, FIELD_P)
    if (x * x - x_squared) % FIELD_P != 0:
        x = x * SQRT_M1 % FIELD_P
    if (x * x - x_squared) % FIELD_P != 0:
        raise ValueError("invalid Edwards point")
    if x & 1 != sign:
        x = FIELD_P - x
    return x


BASE_Y = 4 * _inverse(5) % FIELD_P
BASE_POINT = (_recover_x(BASE_Y, 0), BASE_Y)


def _to_extended(point: tuple[int, int]) -> tuple[int, int, int, int]:
    x, y = point
    return x, y, 1, x * y % FIELD_P


def _from_extended(point: tuple[int, int, int, int]) -> tuple[int, int]:
    x, y, z, _ = point
    inverse_z = _inverse(z)
    return x * inverse_z % FIELD_P, y * inverse_z % FIELD_P


def _extended_add(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % FIELD_P
    b = (y1 + x1) * (y2 + x2) % FIELD_P
    c = 2 * EDWARDS_D * t1 * t2 % FIELD_P
    d = 2 * z1 * z2 % FIELD_P
    e = (b - a) % FIELD_P
    f = (d - c) % FIELD_P
    g = (d + c) % FIELD_P
    h = (b + a) % FIELD_P
    return e * f % FIELD_P, g * h % FIELD_P, f * g % FIELD_P, e * h % FIELD_P


def _extended_double(point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x, y, z, _ = point
    a = x * x % FIELD_P
    b = y * y % FIELD_P
    c = 2 * z * z % FIELD_P
    d = -a % FIELD_P
    e = ((x + y) * (x + y) - a - b) % FIELD_P
    g = (d + b) % FIELD_P
    f = (g - c) % FIELD_P
    h = (d - b) % FIELD_P
    return e * f % FIELD_P, g * h % FIELD_P, f * g % FIELD_P, e * h % FIELD_P


def point_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    return _from_extended(_extended_add(_to_extended(left), _to_extended(right)))


def point_neg(point: tuple[int, int]) -> tuple[int, int]:
    return (-point[0] % FIELD_P, point[1])


def point_sub(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    return point_add(left, point_neg(right))


def scalar_mult(
    scalar: int,
    point: tuple[int, int] = BASE_POINT,
    *,
    reduce: bool = True,
) -> tuple[int, int]:
    if reduce:
        scalar %= SCALAR_Q
    if scalar < 0:
        return scalar_mult(-scalar, point_neg(point), reduce=False)
    result = _to_extended(IDENTITY)
    addend = _to_extended(point)
    while scalar:
        if scalar & 1:
            result = _extended_add(result, addend)
        addend = _extended_double(addend)
        scalar >>= 1
    return _from_extended(result)


def encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    output = bytearray(y.to_bytes(32, "little"))
    output[31] |= (x & 1) << 7
    return bytes(output)


def decode_point(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("Ed25519 point encoding must be 32 bytes")
    raw = bytearray(encoded)
    sign = raw[31] >> 7
    raw[31] &= 0x7F
    y = int.from_bytes(raw, "little")
    if y >= FIELD_P:
        raise ValueError("non-canonical Edwards y coordinate")
    point = (_recover_x(y, sign), y)
    if point == IDENTITY or scalar_mult(SCALAR_Q, point, reduce=False) != IDENTITY:
        raise ValueError("point is not a non-identity prime-order element")
    return point


def scalar_bytes(scalar: int) -> bytes:
    return (scalar % SCALAR_Q).to_bytes(32, "little")


def lp16(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("framed component exceeds u16")
    return len(value).to_bytes(2, "big") + value


def h1_ed25519(message: bytes) -> int:
    digest = hashlib.sha512(CIPHERSUITE_ID + b"rho" + message).digest()
    return int.from_bytes(digest, "little") % SCALAR_Q


def h2_ed25519(message: bytes) -> int:
    digest = hashlib.sha512(message).digest()
    return int.from_bytes(digest, "little") % SCALAR_Q


def context_digest(application: bytes, network: bytes, purpose: bytes) -> bytes:
    for component in (application, network, purpose, CIPHERSUITE_ID):
        if len(component) > 0xFFFF:
            raise ValueError("context component exceeds u16")
    return hashlib.sha256(
        DST_CONTEXT
        + KEY_FAMILY_VERSION.to_bytes(2, "big")
        + lp16(CIPHERSUITE_ID)
        + lp16(PROFILE_ID)
        + lp16(application)
        + lp16(network)
        + lp16(purpose)
    ).digest()


@dataclass(frozen=True)
class PathSegment:
    index: int
    hardened: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.index <= 0xFFFFFFFF:
            raise ValueError("path index exceeds u32")

    @property
    def kind(self) -> int:
        return 1 if self.hardened else 0

    def __str__(self) -> str:
        suffix = "'" if self.hardened else ""
        return f"{self.index}{suffix}"


@dataclass(frozen=True)
class DerivationPath:
    segments: tuple[PathSegment, ...] = ()

    def __post_init__(self) -> None:
        if len(self.segments) > MAX_PATH_DEPTH:
            raise ValueError("path too deep")

    @classmethod
    def parse(cls, text: str) -> "DerivationPath":
        if text == "m":
            return cls()
        if not text.startswith("m/"):
            raise ValueError("non-canonical path")
        tokens = text[2:].split("/")
        if not tokens or any(not token for token in tokens):
            raise ValueError("non-canonical path")
        segments: list[PathSegment] = []
        for token in tokens:
            hardened = token.endswith("'")
            digits = token[:-1] if hardened else token
            if not digits or not digits.isascii() or not digits.isdecimal():
                raise ValueError("non-canonical path")
            if len(digits) > 1 and digits.startswith("0"):
                raise ValueError("non-canonical path")
            try:
                index = int(digits, 10)
            except ValueError as error:
                raise ValueError("non-canonical path") from error
            segments.append(PathSegment(index=index, hardened=hardened))
        path = cls(tuple(segments))
        if str(path) != text:
            raise ValueError("non-canonical path")
        return path

    def child(self, segment: PathSegment) -> "DerivationPath":
        return DerivationPath(self.segments + (segment,))

    def to_bytes(self) -> bytes:
        output = bytearray(PATH_ENCODING_VERSION.to_bytes(2, "big"))
        output.extend(len(self.segments).to_bytes(2, "big"))
        for segment in self.segments:
            output.append(segment.kind)
            output.extend(segment.index.to_bytes(4, "big"))
        return bytes(output)

    @classmethod
    def from_bytes(cls, encoded: bytes) -> "DerivationPath":
        if len(encoded) < 4:
            raise ValueError("malformed path encoding")
        version = int.from_bytes(encoded[0:2], "big")
        if version != PATH_ENCODING_VERSION:
            raise ValueError("unsupported path version")
        count = int.from_bytes(encoded[2:4], "big")
        if count > MAX_PATH_DEPTH or len(encoded) != 4 + count * 5:
            raise ValueError("malformed path encoding")
        segments: list[PathSegment] = []
        offset = 4
        for _ in range(count):
            kind = encoded[offset]
            index = int.from_bytes(encoded[offset + 1 : offset + 5], "big")
            if kind not in (0, 1):
                raise ValueError("unknown path segment kind")
            segments.append(PathSegment(index=index, hardened=kind == 1))
            offset += 5
        return cls(tuple(segments))

    def __str__(self) -> str:
        return "m" + "".join(f"/{segment}" for segment in self.segments)


@dataclass(frozen=True)
class Node:
    public_key: tuple[int, int]
    derivation_key: bytes
    context: bytes
    path: DerivationPath = DerivationPath()
    cumulative_tweak: int = 0

    def __post_init__(self) -> None:
        if len(self.derivation_key) != 32:
            raise ValueError("derivation key must be 32 bytes")
        if len(self.context) != 32:
            raise ValueError("context digest must be 32 bytes")


def derive_child(node: Node, segment: PathSegment) -> Node:
    if segment.hardened:
        raise ValueError("hardened derivation is unsupported")
    parent_encoded = encode_point(node.public_key)
    for retry in range(MAX_EDGE_RETRIES):
        common = (
            DST_EDGE
            + KEY_FAMILY_VERSION.to_bytes(2, "big")
            + lp16(CIPHERSUITE_ID)
            + lp16(PROFILE_ID)
            + node.context
            + lp16(parent_encoded)
            + bytes([segment.kind])
            + segment.index.to_bytes(4, "big")
            + retry.to_bytes(2, "big")
        )
        tweak_prf = hmac.new(
            node.derivation_key,
            DST_TWEAK_PRF + common,
            hashlib.sha512,
        ).digest()
        tweak = h1_ed25519(DST_HASH_TO_SCALAR + tweak_prf)
        if tweak == 0:
            continue
        child_public = point_add(node.public_key, scalar_mult(tweak))
        if child_public == IDENTITY:
            continue
        child_key = hmac.new(
            node.derivation_key,
            DST_CHILD_KEY + common,
            hashlib.sha512,
        ).digest()[:32]
        return Node(
            public_key=child_public,
            derivation_key=child_key,
            context=node.context,
            path=node.path.child(segment),
            cumulative_tweak=(node.cumulative_tweak + tweak) % SCALAR_Q,
        )
    raise RuntimeError("derivation retry exhausted")


def derive_path(root: Node, path: DerivationPath) -> Node:
    node = root
    for segment in path.segments:
        node = derive_child(node, segment)
    return node


def polynomial_evaluate(coefficients: Sequence[int], x: int) -> int:
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * x + coefficient) % SCALAR_Q
    return result


def lagrange_at_zero(identifier: int, subset: Sequence[int]) -> int:
    numerator = 1
    denominator = 1
    for other in subset:
        if other == identifier:
            continue
        numerator = numerator * other % SCALAR_Q
        denominator = denominator * (other - identifier) % SCALAR_Q
    return numerator * pow(denominator % SCALAR_Q, SCALAR_Q - 2, SCALAR_Q) % SCALAR_Q


def interpolate_at_zero(shares: dict[int, int], subset: Sequence[int]) -> int:
    return sum(lagrange_at_zero(identifier, subset) * shares[identifier] for identifier in subset) % SCALAR_Q


def deterministic_scalar(label: bytes) -> int:
    scalar = int.from_bytes(hashlib.sha512(label).digest(), "little") % SCALAR_Q
    return scalar or 1


def make_shares(secret: int, threshold: int, participants: int, label: bytes) -> dict[int, int]:
    if not 1 <= threshold <= participants:
        raise ValueError("invalid threshold")
    coefficients = [secret]
    for index in range(1, threshold):
        coefficients.append(deterministic_scalar(label + b"/coefficient/" + index.to_bytes(2, "big")))
    return {
        identifier: polynomial_evaluate(coefficients, identifier)
        for identifier in range(1, participants + 1)
    }


def assert_threshold_invariant(shares: dict[int, int], threshold: int, expected: int) -> None:
    for subset in itertools.combinations(sorted(shares), threshold):
        assert sum(lagrange_at_zero(identifier, subset) for identifier in subset) % SCALAR_Q == 1
        assert interpolate_at_zero(shares, subset) == expected


def sign(secret: int, public_key: tuple[int, int], message: bytes, nonce_label: bytes) -> bytes:
    nonce = deterministic_scalar(b"FROST-HD-v1/test-nonce/" + nonce_label + message)
    commitment = scalar_mult(nonce)
    challenge = h2_ed25519(encode_point(commitment) + encode_point(public_key) + message)
    response = (nonce + challenge * secret) % SCALAR_Q
    return encode_point(commitment) + scalar_bytes(response)


def verify(public_key: tuple[int, int], message: bytes, signature: bytes) -> bool:
    if len(signature) != 64:
        return False
    try:
        commitment = decode_point(signature[:32])
    except ValueError:
        return False
    response = int.from_bytes(signature[32:], "little")
    if response >= SCALAR_Q:
        return False
    challenge = h2_ed25519(signature[:32] + encode_point(public_key) + message)
    return scalar_mult(response) == point_add(commitment, scalar_mult(challenge, public_key))


def build_vectors() -> dict[str, object]:
    application = b"org.example.wallet"
    network = b"solana-devnet"
    purpose = b"threshold-child-keys"
    context = context_digest(application, network, purpose)
    root_derivation_key = bytes(range(32))
    root_secret = deterministic_scalar(b"FROST-HD-v1/reference/root-secret")
    root_public = scalar_mult(root_secret)
    root = Node(root_public, root_derivation_key, context)
    message = b"generic FROST-HD reference signature"
    paths = [
        DerivationPath.parse("m/0"),
        DerivationPath.parse("m/1/42"),
        DerivationPath.parse("m/7/3/999"),
        DerivationPath.parse("m/4294967295"),
    ]

    configurations = [(2, 2), (2, 3), (3, 5)]
    root_shares: dict[str, dict[int, int]] = {}
    for threshold, participants in configurations:
        key = f"{threshold}-of-{participants}"
        shares = make_shares(root_secret, threshold, participants, key.encode())
        assert_threshold_invariant(shares, threshold, root_secret)
        root_shares[key] = shares

    path_vectors: list[dict[str, object]] = []
    seen_public: set[bytes] = set()
    for path in paths:
        child = derive_path(root, path)
        stepwise = root
        for segment in path.segments:
            stepwise = derive_child(stepwise, segment)
        assert child == stepwise

        child_secret = (root_secret + child.cumulative_tweak) % SCALAR_Q
        assert scalar_mult(child_secret) == child.public_key
        encoded_child = encode_point(child.public_key)
        assert encoded_child not in seen_public
        seen_public.add(encoded_child)

        threshold_checks: dict[str, str] = {}
        for configuration, shares in root_shares.items():
            threshold = int(configuration.split("-")[0])
            child_shares = {
                identifier: (share + child.cumulative_tweak) % SCALAR_Q
                for identifier, share in shares.items()
            }
            assert_threshold_invariant(child_shares, threshold, child_secret)
            for identifier, child_share in child_shares.items():
                expected_public = point_add(
                    scalar_mult(shares[identifier]),
                    scalar_mult(child.cumulative_tweak),
                )
                assert scalar_mult(child_share) == expected_public
            threshold_checks[configuration] = "pass"

        signature = sign(child_secret, child.public_key, message, str(path).encode())
        assert verify(child.public_key, message, signature)
        assert not verify(root.public_key, message, signature)

        path_vectors.append(
            {
                "path": str(path),
                "path_encoding_hex": path.to_bytes().hex(),
                "cumulative_tweak_le_hex": scalar_bytes(child.cumulative_tweak).hex(),
                "derivation_key_hex": child.derivation_key.hex(),
                "public_key_hex": encoded_child.hex(),
                "signature_hex": signature.hex(),
                "threshold_checks": threshold_checks,
            }
        )

    # Cross-path recovery of a 2-of-3 root from two leaked child shares.
    shares_2_of_3 = root_shares["2-of-3"]
    child_a = derive_path(root, paths[0])
    child_b = derive_path(root, paths[2])
    leaked_a = (shares_2_of_3[1] + child_a.cumulative_tweak) % SCALAR_Q
    leaked_b = (shares_2_of_3[2] + child_b.cumulative_tweak) % SCALAR_Q
    recovered = interpolate_at_zero(
        {
            1: (leaked_a - child_a.cumulative_tweak) % SCALAR_Q,
            2: (leaked_b - child_b.cumulative_tweak) % SCALAR_Q,
        },
        [1, 2],
    )
    assert recovered == root_secret

    return {
        "specification": "FROST-HD-v1 research draft",
        "warning": "Deterministic test material only. Never use these secrets.",
        "ciphersuite_id": CIPHERSUITE_ID.decode(),
        "profile_id": PROFILE_ID.decode(),
        "application": application.decode(),
        "network": network.decode(),
        "purpose": purpose.decode(),
        "context_digest_hex": context.hex(),
        "root_derivation_key_hex": root_derivation_key.hex(),
        "root_secret_le_hex": scalar_bytes(root_secret).hex(),
        "root_public_key_hex": encode_point(root_public).hex(),
        "message_hex": message.hex(),
        "paths": path_vectors,
        "cross_path_recovery": {
            "configuration": "2-of-3",
            "participant_1_path": str(paths[0]),
            "participant_2_path": str(paths[2]),
            "recovered_root_secret_le_hex": scalar_bytes(recovered).hex(),
            "matches_root": recovered == root_secret,
        },
    }


def write_vectors(output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build_vectors(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    default_output = Path(__file__).resolve().parents[1] / "vectors" / "frost-hd-v1-ed25519.json"
    write_vectors(default_output)
    print(f"wrote {default_output}")
