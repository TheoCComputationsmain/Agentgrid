"""Local model of AgentGrid's parent/child scope check.

This file mirrors the rule used by the hosted API: when a handoff declares a
``parent_handoff_id``, its scope must stay inside the parent's scope. Only two
keys are enforced: ``allowed`` (set subset) and ``max_actions`` (integer ceiling).

No network access and no API key are needed for this demo.
"""
from __future__ import annotations

from typing import Any

PARENT_SCOPE: dict[str, Any] = {"allowed": ["read"], "max_actions": 2}

NARROWED_SCOPE: dict[str, Any] = {"allowed": ["read"], "max_actions": 1}
WIDENED_ALLOWED_SCOPE: dict[str, Any] = {
    "allowed": ["read", "write"],
    "max_actions": 2,
}
WIDENED_ACTIONS_SCOPE: dict[str, Any] = {"allowed": ["read"], "max_actions": 5}
UNKNOWN_KEY_SCOPE: dict[str, Any] = {"allowed": ["read"], "max_actions": 2, "note": "ok"}


def scope_is_subset(child: dict[str, Any], parent: dict[str, Any]) -> bool:
    """Return True only when ``child`` does not widen ``parent``.

    This is the same check used by the service for nested handoffs:
    ``allowed`` must be a subset when present, and ``max_actions`` may not be
    higher when present. Other keys are signed and stored, but not enforced.
    """
    if not isinstance(child, dict) or not isinstance(parent, dict):
        return False
    if "allowed" in child:
        if "allowed" not in parent:
            return False
        if not isinstance(child["allowed"], list) or not isinstance(parent["allowed"], list):
            return False
        if not set(child["allowed"]).issubset(set(parent["allowed"])):
            return False
    if "max_actions" in child:
        if "max_actions" not in parent:
            return False
        try:
            if int(child["max_actions"]) > int(parent["max_actions"]):
                return False
        except (TypeError, ValueError):
            return False
    return True


def cases() -> tuple[tuple[str, dict[str, Any], bool], ...]:
    """Return the demo cases as (label, child_scope, should_be_accepted)."""
    return (
        ("narrow both fields", NARROWED_SCOPE, True),
        ("same scope", PARENT_SCOPE, True),
        ("extra non-enforced key", UNKNOWN_KEY_SCOPE, True),
        ("add write capability", WIDENED_ALLOWED_SCOPE, False),
        ("raise max_actions", WIDENED_ACTIONS_SCOPE, False),
    )


def run_demo() -> None:
    print("Parent scope: " + str(PARENT_SCOPE))
    print("-" * 58)
    for label, child, expected in cases():
        accepted = scope_is_subset(child, parent=PARENT_SCOPE)
        marker = "ACCEPT" if accepted else "REJECT"
        verdict = "ok" if accepted == expected else "UNEXPECTED"
        print(f"{marker:6}  {label:26} child={child}  [{verdict}]")
        assert accepted == expected, label
    print("-" * 58)
    print("Local check passed. Live mode proves the hosted API rejects the same widened cases.")


if __name__ == "__main__":
    run_demo()
