import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scope_chain import (  # noqa: E402
    NARROWED_SCOPE,
    PARENT_SCOPE,
    WIDENED_ACTIONS_SCOPE,
    WIDENED_ALLOWED_SCOPE,
    cases,
    scope_is_subset,
)


class ScopeChainTests(unittest.TestCase):
    def test_documented_cases_match_expected_verdicts(self) -> None:
        for label, child, expected in cases():
            with self.subTest(label=label):
                self.assertEqual(scope_is_subset(child, PARENT_SCOPE), expected)

    def test_narrowing_is_allowed(self) -> None:
        self.assertTrue(scope_is_subset(NARROWED_SCOPE, PARENT_SCOPE))

    def test_added_capability_is_rejected(self) -> None:
        self.assertFalse(scope_is_subset(WIDENED_ALLOWED_SCOPE, PARENT_SCOPE))

    def test_higher_max_actions_is_rejected(self) -> None:
        self.assertFalse(scope_is_subset(WIDENED_ACTIONS_SCOPE, PARENT_SCOPE))

    def test_missing_parent_key_is_rejected(self) -> None:
        self.assertFalse(scope_is_subset({"max_actions": 2}, {"allowed": ["read"]}))

    def test_non_dict_input_is_rejected(self) -> None:
        self.assertFalse(scope_is_subset([], PARENT_SCOPE))


if __name__ == "__main__":
    unittest.main()
