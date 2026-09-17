"""
Helper functions for experience integration.
"""
import json
from hashlib import sha256
from typing import Any


def derive_fingerprint(goal: Any, granularity: str = "exact") -> str:
    """
    Derive fingerprint from goal for experience lookup.
    
    Args:
        goal: Goal object (typically dict)
        granularity: "exact" (default) | "template" (future) | "category" (future)
    
    Returns:
        SHA256 hex digest of goal
    """
    if granularity != "exact":
        raise ValueError(f"Unsupported granularity: {granularity}. Only 'exact' is implemented.")
    
    # Canonical JSON serialization
    goal_json = json.dumps(goal, sort_keys=True, ensure_ascii=False)
    return sha256(goal_json.encode('utf-8')).hexdigest()
