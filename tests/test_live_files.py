#!/usr/bin/env python3
"""Live test with actual PDF files from downloads folder"""

import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from skills.file_analyst.scripts.file_analyst import analyze_contract, analyze_with_profile, read_pdf
from skills.file_analyst.scripts.profile_loader import detect_profile

DOWNLOADS = os.path.join(project_root, "downloads")


def test_file(filepath, expected_profile=None):
    """Test a single file with profile detection and analysis"""
    print(f"\n{'=' * 60}")
    print(f"Testing: {os.path.basename(filepath)}")
    print("=" * 60)

    if not os.path.exists(filepath):
        print(f"  ✗ File not found: {filepath}")
        return False

    try:
        # Step 1: Read PDF (with auto OCR if needed)
        print("\n[1] Reading PDF...")
        text = read_pdf(filepath, pages=5, auto_ocr=True)
        if not text or len(text.strip()) < 50:
            print(f"  ✗ No text extracted (length: {len(text) if text else 0})")
            return False
        print(f"  ✓ Extracted {len(text)} chars")
        print(f"  Preview: {text[:100]}...")

        # Step 2: Detect profile
        print("\n[2] Detecting profile...")
        detected = detect_profile(text, filepath)
        print(f"  Detected: {detected}")
        if expected_profile:
            match = "✓" if detected == expected_profile else "✗"
            print(f"  {match} Expected: {expected_profile}")

        # Step 3: Try contract analysis if it's a contract
        if detected and detected.endswith("_contract"):
            print("\n[3] Running contract analysis...")
            result = analyze_contract(text, filepath)
            print(f"  Result preview: {result[:200]}...")

        # Step 4: Try general profile analysis
        elif detected:
            print("\n[3] Running profile analysis...")
            result = analyze_with_profile(text, filepath)
            print(f"  Result preview: {result[:200]}...")

        return True

    except Exception as e:
        print(f"  ✗ Error: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    print("=" * 60)
    print("LIVE FILE TEST - Testing with real PDF files")
    print("=" * 60)

    test_files = [
        (os.path.join(DOWNLOADS, "sample_contract.pdf"), "rental_contract"),
        (os.path.join(DOWNLOADS, "MandatoryCarInsurancePolicy.pdf"), "car_insurance_policy"),
        (os.path.join(DOWNLOADS, "חוזה שכירות.pdf"), "rental_contract"),
    ]

    results = []
    for filepath, expected in test_files:
        if os.path.exists(filepath):
            success = test_file(filepath, expected)
            results.append((os.path.basename(filepath), success))
        else:
            print(f"\n✗ File not found: {filepath}")
            results.append((os.path.basename(filepath), False))

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    passed = sum(1 for _, s in results if s)
    for name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {status}: {name}")

    print(f"\nOverall: {passed}/{len(results)} files processed successfully")

    return passed == len(results)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
