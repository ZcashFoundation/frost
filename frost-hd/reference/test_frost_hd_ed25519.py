from __future__ import annotations

import itertools
import json
import tempfile
import unittest
from pathlib import Path

from frost_hd_ed25519 import (
    BASE_POINT,
    DerivationPath,
    FIELD_P,
    Node,
    PathSegment,
    SCALAR_Q,
    assert_threshold_invariant,
    build_vectors,
    context_digest,
    decode_point,
    derive_child,
    derive_path,
    encode_point,
    interpolate_at_zero,
    make_shares,
    point_add,
    point_neg,
    scalar_mult,
    verify,
    write_vectors,
)

POINT_ENCODING_BYTES = 32
POINT_SIGN_BIT = 1 << 255


class PointDecodingTests(unittest.TestCase):
    def test_valid_points_round_trip(self) -> None:
        for point in (BASE_POINT, point_neg(BASE_POINT)):
            with self.subTest(point=point):
                self.assertEqual(decode_point(encode_point(point)), point)

    def test_zero_x_points_are_rejected(self) -> None:
        for y in (1, FIELD_P - 1):
            for sign in (0, 1):
                encoded = (y | sign * POINT_SIGN_BIT).to_bytes(POINT_ENCODING_BYTES, "little")
                with self.subTest(y=y, sign=sign), self.assertRaises(ValueError):
                    decode_point(encoded)

    def test_non_canonical_y_is_rejected(self) -> None:
        for y in (FIELD_P, FIELD_P + 1, POINT_SIGN_BIT - 1):
            with self.subTest(y=y), self.assertRaises(ValueError):
                decode_point(y.to_bytes(POINT_ENCODING_BYTES, "little"))

    def test_invalid_lengths_are_rejected(self) -> None:
        for length in (0, POINT_ENCODING_BYTES - 1, POINT_ENCODING_BYTES + 1):
            with self.subTest(length=length), self.assertRaises(ValueError):
                decode_point(bytes(length))

    def test_verify_rejects_negative_zero_commitment(self) -> None:
        commitment = (1 | POINT_SIGN_BIT).to_bytes(POINT_ENCODING_BYTES, "little")
        signature = commitment + bytes(POINT_ENCODING_BYTES)
        self.assertFalse(verify(BASE_POINT, b"invalid commitment", signature))


class PathTests(unittest.TestCase):
    def test_text_and_binary_round_trip(self) -> None:
        for text in ("m", "m/0", "m/1/4294967295", "m/0'/1"):
            path = DerivationPath.parse(text)
            self.assertEqual(str(path), text)
            self.assertEqual(DerivationPath.from_bytes(path.to_bytes()), path)

    def test_non_canonical_paths_are_rejected(self) -> None:
        for text in ("", "M", "m/", "m//1", "m/+1", "m/-1", "m/01", "m/1''"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                DerivationPath.parse(text)

    def test_hardened_path_is_typed_but_not_derivable(self) -> None:
        root = Node(BASE_POINT, bytes(32), bytes(32))
        with self.assertRaisesRegex(ValueError, "hardened"):
            derive_path(root, DerivationPath.parse("m/0'/1"))


class AlgebraTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root_secret = 123456789 % SCALAR_Q
        self.root = Node(
            scalar_mult(self.root_secret),
            bytes(range(32)),
            context_digest(b"app", b"network", b"purpose"),
        )

    def test_thresholds_and_all_qualified_subsets(self) -> None:
        for threshold, participants in ((2, 2), (2, 3), (3, 5)):
            shares = make_shares(self.root_secret, threshold, participants, b"case")
            assert_threshold_invariant(shares, threshold, self.root_secret)
            child = derive_path(self.root, DerivationPath.parse("m/1/42"))
            child_secret = (self.root_secret + child.cumulative_tweak) % SCALAR_Q
            child_shares = {
                identifier: (share + child.cumulative_tweak) % SCALAR_Q
                for identifier, share in shares.items()
            }
            assert_threshold_invariant(child_shares, threshold, child_secret)

    def test_public_and_private_derivation_agree(self) -> None:
        shares = make_shares(self.root_secret, 2, 3, b"agreement")
        child = derive_path(self.root, DerivationPath.parse("m/7/3/999"))
        for identifier, parent_share in shares.items():
            child_share = (parent_share + child.cumulative_tweak) % SCALAR_Q
            self.assertEqual(
                scalar_mult(child_share),
                point_add(scalar_mult(parent_share), scalar_mult(child.cumulative_tweak)),
                identifier,
            )

    def test_direct_path_equals_stepwise(self) -> None:
        path = DerivationPath.parse("m/1/42/9")
        direct = derive_path(self.root, path)
        stepwise = self.root
        for segment in path.segments:
            stepwise = derive_child(stepwise, segment)
        self.assertEqual(direct, stepwise)

    def test_distinct_branches_are_distinct(self) -> None:
        paths = [DerivationPath.parse(text) for text in ("m/0", "m/1", "m/1/0", "m/0/1")]
        keys = {encode_point(derive_path(self.root, path).public_key) for path in paths}
        self.assertEqual(len(keys), len(paths))

    def test_wrong_context_or_derivation_key_changes_family(self) -> None:
        path = DerivationPath.parse("m/1/42")
        expected = derive_path(self.root, path)
        wrong_context = Node(self.root.public_key, self.root.derivation_key, bytes([1]) * 32)
        wrong_key = Node(self.root.public_key, bytes([2]) * 32, self.root.context)
        self.assertNotEqual(derive_path(wrong_context, path).public_key, expected.public_key)
        self.assertNotEqual(derive_path(wrong_key, path).public_key, expected.public_key)

    def test_cross_path_leaks_accumulate_to_root_threshold(self) -> None:
        shares = make_shares(self.root_secret, 2, 3, b"cross-path")
        child_a = derive_path(self.root, DerivationPath.parse("m/0"))
        child_b = derive_path(self.root, DerivationPath.parse("m/99/3"))
        leaked_child_1 = (shares[1] + child_a.cumulative_tweak) % SCALAR_Q
        leaked_child_2 = (shares[2] + child_b.cumulative_tweak) % SCALAR_Q
        normalized = {
            1: (leaked_child_1 - child_a.cumulative_tweak) % SCALAR_Q,
            2: (leaked_child_2 - child_b.cumulative_tweak) % SCALAR_Q,
        }
        self.assertEqual(interpolate_at_zero(normalized, [1, 2]), self.root_secret)

    def test_same_participant_multiple_paths_adds_no_shamir_rank(self) -> None:
        shares = make_shares(self.root_secret, 2, 3, b"rank")
        participant = 1
        recovered = set()
        for text in ("m/0", "m/1", "m/7/3"):
            child = derive_path(self.root, DerivationPath.parse(text))
            leaked = (shares[participant] + child.cumulative_tweak) % SCALAR_Q
            recovered.add((leaked - child.cumulative_tweak) % SCALAR_Q)
        self.assertEqual(recovered, {shares[participant]})


class VectorTests(unittest.TestCase):
    def test_vector_generation_is_deterministic(self) -> None:
        first = build_vectors()
        second = build_vectors()
        self.assertEqual(first, second)
        self.assertTrue(first["cross_path_recovery"]["matches_root"])

    def test_checked_in_vectors_match_reference(self) -> None:
        vector_path = Path(__file__).resolve().parents[1] / "vectors" / "frost-hd-v1-ed25519.json"
        checked_in = json.loads(vector_path.read_text(encoding="utf-8"))
        self.assertEqual(checked_in, build_vectors())

    def test_write_vectors_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "vectors.json"
            write_vectors(output)
            self.assertEqual(json.loads(output.read_text()), build_vectors())


if __name__ == "__main__":
    unittest.main()
