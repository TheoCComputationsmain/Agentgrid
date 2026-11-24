import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from task_binding import (  # noqa: E402
    TASK,
    TAMPERED_TASK,
    b64e,
    build_payload,
    canonical,
    sign_payload,
    task_digest,
    verify_payload,
)


class TaskBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private = Ed25519PrivateKey.generate()
        cls.public_b64 = b64e(
            cls.private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )

    def test_digest_is_stable_and_lowercase_hex(self) -> None:
        digest = task_digest(TASK)
        self.assertEqual(digest, task_digest(TASK))
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, digest.lower())

    def test_different_task_changes_hash(self) -> None:
        self.assertNotEqual(task_digest(TASK), task_digest(TAMPERED_TASK))

    def test_payload_contains_hash_not_raw_task(self) -> None:
        payload = build_payload(TASK)
        self.assertNotIn("task", payload)
        self.assertEqual(payload["task_hash"], task_digest(TASK))

    def test_signature_verifies_original_payload(self) -> None:
        payload = build_payload(TASK)
        signature = sign_payload(payload, self.private)
        self.assertTrue(verify_payload(payload, signature, self.public_b64))

    def test_signature_fails_after_task_hash_tampering(self) -> None:
        payload = build_payload(TASK)
        signature = sign_payload(payload, self.private)
        tampered = dict(payload)
        tampered["task_hash"] = task_digest(TAMPERED_TASK)
        self.assertFalse(verify_payload(tampered, signature, self.public_b64))

    def test_canonical_json_is_order_independent(self) -> None:
        first = canonical({"b": 1, "a": 2})
        second = canonical({"a": 2, "b": 1})
        self.assertEqual(first, second)
        self.assertEqual(first, b'{"a":2,"b":1}')


if __name__ == "__main__":
    unittest.main()
