"""
Profile Loader - Dynamic loading of analysis profiles from split JSON files.

Replaces the monolithic analysis_profiles.json with modular category-based loading.
Benefits:
- Reduced memory footprint (load only needed profiles)
- Faster startup for specific document types
- Easier maintenance and updates per category
"""

import json
import sys
from pathlib import Path
from typing import Any

# Cache for loaded profiles
_profile_cache: dict[str, dict[str, Any]] = {}
_index_cache: dict[str, Any] | None = None


def _get_profiles_dir() -> Path:
    """Return the path to the profiles directory."""
    return Path(__file__).resolve().parent.parent / "config" / "profiles"


def load_index() -> dict[str, Any]:
    """Load the profile index mapping."""
    global _index_cache
    if _index_cache is not None:
        return _index_cache

    index_path = _get_profiles_dir() / "_index.json"
    try:
        with open(index_path, encoding="utf-8") as f:
            _index_cache = json.load(f)
        return _index_cache
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise RuntimeError(f"Failed to load profile index from {index_path}: {e}")


def _find_profile_location(profile_name: str) -> tuple[str, Path] | None:
    """Find which category contains the given profile."""
    index = load_index()
    for category, info in index.get("categories", {}).items():
        if profile_name in info.get("profiles", []):
            return category, _get_profiles_dir() / info["path"]
    return None


def load_profile(profile_name: str) -> dict[str, Any] | None:
    """
    Load a single profile by name.

    Args:
        profile_name: The profile identifier (e.g., 'rental_contract', 'car_insurance_policy')

    Returns:
        The profile dict or None if not found
    """
    # Check cache first
    if profile_name in _profile_cache:
        return _profile_cache[profile_name]

    location = _find_profile_location(profile_name)
    if location is None:
        return None

    category, file_path = location

    try:
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)

        profiles = data.get("profiles", {})
        if profile_name not in profiles:
            return None

        profile = profiles[profile_name]
        _profile_cache[profile_name] = profile
        return profile
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def load_category(category: str) -> dict[str, dict[str, Any]]:
    """
    Load all profiles from a specific category.

    Args:
        category: Category name (e.g., 'contracts', 'insurance', 'financial')

    Returns:
        Dict mapping profile names to their definitions
    """
    index = load_index()
    cat_info = index.get("categories", {}).get(category)
    if cat_info is None:
        return {}

    file_path = _get_profiles_dir() / cat_info["path"]

    try:
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)

        profiles = data.get("profiles", {})
        # Cache all loaded profiles
        _profile_cache.update(profiles)
        return profiles
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def load_all_profiles() -> dict[str, dict[str, Any]]:
    """
    Load all profiles from all categories.
    Use sparingly - defeats the purpose of modular loading.
    """
    index = load_index()
    all_profiles: dict[str, dict[str, Any]] = {}

    for category in index.get("categories", {}):
        cat_profiles = load_category(category)
        all_profiles.update(cat_profiles)

    return all_profiles


def list_profiles() -> dict[str, list[str]]:
    """List all available profiles grouped by category."""
    index = load_index()
    return {
        cat: info.get("profiles", [])
        for cat, info in index.get("categories", {}).items()
    }


def list_categories() -> list[str]:
    """List all available profile categories."""
    index = load_index()
    return list(index.get("categories", {}).keys())


def get_profile_category(profile_name: str) -> str | None:
    """Get the category for a specific profile."""
    index = load_index()
    for category, info in index.get("categories", {}).items():
        if profile_name in info.get("profiles", []):
            return category
    return None


def clear_cache() -> None:
    """Clear the profile cache."""
    global _profile_cache, _index_cache
    _profile_cache = {}
    _index_cache = None


def detect_profile(text: str, filename: str = "") -> str | None:
    """
    Detect which profile best matches the given text and filename.
    Uses both content keywords and filename patterns for robust detection.

    Returns:
        Profile name or None if no match
    """
    from _profile_patterns import FILENAME_PATTERNS, KEYWORDS_MAP

    text_lower = text.lower()
    filename_lower = filename.lower()

    # Score from filename patterns
    filename_scores: dict[str, int] = {}
    for profile, patterns in FILENAME_PATTERNS.items():
        for pattern in patterns:
            if pattern in filename_lower:
                filename_scores[profile] = filename_scores.get(profile, 0) + 5

    # Combine filename and content scores
    scores: dict[str, int] = dict(filename_scores)

    for profile, keywords in KEYWORDS_MAP.items():
        for kw in keywords:
            if kw in text_lower:
                scores[profile] = scores.get(profile, 0) + 2
            if kw in filename_lower:
                scores[profile] = scores.get(profile, 0) + 3

    if scores:
        best_match = max(scores, key=scores.get)
        print(
            f"[detect_profile] Scores: {dict(sorted(scores.items(), key=lambda x: -x[1])[:3])}",
            file=sys.stderr,
        )
        print(f"[detect_profile] Selected: {best_match}", file=sys.stderr)
        return best_match

    return None
