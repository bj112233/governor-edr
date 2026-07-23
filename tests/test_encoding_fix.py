#!/usr/bin/env python3
"""Test font encoding fix"""

import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from skills.file_analyst.scripts.file_analyst import _fix_custom_font_encoding, detect_profile, read_pdf

# Test 1: Encoding fix function
print("=" * 50)
print("TEST 1: _fix_custom_font_encoding")
print("=" * 50)

gibberish = "MWPIVOIVA-- 2025 7ANST WN 3103"
fixed = _fix_custom_font_encoding(gibberish)
print(f"Input:  {gibberish}")
print(f"Output: {fixed}")
print()

# Test 2: Read actual PDF
print("=" * 50)
print("TEST 2: Read Hebrew Contract PDF")
print("=" * 50)

path = os.path.join(project_root, "downloads", "sample_contract.pdf")
print(f"File: {path}")

try:
    text = read_pdf(path, pages=1)
    print(f"\nExtracted {len(text)} characters")
    print("\n--- First 600 chars ---")
    print(text[:600])

    # Detect profile
    print("\n--- Profile Detection ---")
    profile = detect_profile(text, path)
    print(f"Detected profile: {profile}")

    # Check if Hebrew was fixed
    hebrew_chars = sum(1 for c in text if "\u0590" <= c <= "\u05ff")
    print(f"\nHebrew characters: {hebrew_chars}")
    if hebrew_chars > 50:
        print("✓ SUCCESS: Hebrew text detected!")
    else:
        print("⚠ WARNING: Very few Hebrew characters found")

except Exception as e:
    print(f"ERROR: {e}")
    import traceback

    traceback.print_exc()

print("\n" + "=" * 50)
print("TEST COMPLETE")
print("=" * 50)
