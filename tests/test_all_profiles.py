#!/usr/bin/env python3
"""Live test of all 28 profile loader functions"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills", "file_analyst", "scripts"))

from profile_loader import detect_profile, get_profile_category, list_profiles, load_category, load_index, load_profile


def test_all_profiles():
    print("=" * 60)
    print("LIVE PROFILE TEST - Testing all 28 profiles")
    print("=" * 60)

    # 1. Test index loading
    print("\n[1] Loading index...")
    try:
        index = load_index()
        print(f"  ✓ Index loaded: {index.get('profile_count', 'N/A')} profiles declared")
    except Exception as e:
        print(f"  ✗ Index load failed: {e}")
        return False

    # 2. Test list_profiles
    print("\n[2] Listing all profiles by category...")
    all_profiles = list_profiles()
    total = sum(len(v) for v in all_profiles.values())
    print(f"  Total profiles found: {total}")
    for cat, profiles in all_profiles.items():
        print(f"    - {cat}: {len(profiles)} profiles")
        for p in profiles:
            print(f"        • {p}")

    # 3. Test individual profile loading
    print("\n[3] Testing individual profile loading...")
    failed = []
    passed = []

    for cat, profiles in all_profiles.items():
        for profile_name in profiles:
            try:
                profile = load_profile(profile_name)
                if profile:
                    desc = profile.get("description", "N/A")[:40]
                    print(f"  ✓ {profile_name}: {desc}...")
                    passed.append(profile_name)
                else:
                    print(f"  ✗ {profile_name}: returned None")
                    failed.append(profile_name)
            except Exception as e:
                print(f"  ✗ {profile_name}: {e}")
                failed.append(profile_name)

    # 4. Test category loading
    print("\n[4] Testing category loading...")
    for cat in all_profiles.keys():
        try:
            cat_data = load_category(cat)
            print(f"  ✓ {cat}: {len(cat_data)} profiles loaded")
        except Exception as e:
            print(f"  ✗ {cat}: {e}")

    # 5. Test profile detection with sample texts
    print("\n[5] Testing profile detection...")
    test_cases = [
        ("חוזה שכירות דירה עם שכר דירה של 5000 שח", "rental_contract"),
        ("employment contract with salary and benefits", "employment_contract"),
        ("פוליסת ביטוח רכב חובה ומקיף", "car_insurance_policy"),
        ("דוח רפואי עם אבחנה ותוצאות בדיקה", "medical_report"),
        ("תלוש שכר עם ניכויים לביטוח לאומי", "payslip"),
        ("פסק דין של בית משפט מחוזי", "court_ruling"),
        ("החלטת דירקטוריון של חברה", "board_resolution"),
        ("מדריך טכני עם מפרט IEC", "technical_manual"),
    ]

    detect_passed = 0
    for text, expected in test_cases:
        detected = detect_profile(text, "")
        status = "✓" if detected == expected else "✗"
        if detected == expected:
            detect_passed += 1
        print(f"  {status} '{text[:30]}...' -> {detected} (expected: {expected})")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Profiles loaded:     {len(passed)}/28")
    print(f"Profiles failed:     {len(failed)}")
    print(f"Detection tests:     {detect_passed}/{len(test_cases)}")

    if failed:
        print(f"\nFailed profiles: {', '.join(failed)}")

    success = len(failed) == 0 and len(passed) == 28
    print(f"\nOverall: {'✓ ALL TESTS PASSED' if success else '✗ SOME TESTS FAILED'}")

    assert success, f"{len(failed)} profiles failed: {', '.join(failed)}"


if __name__ == "__main__":
    success = test_all_profiles()
    sys.exit(0 if success else 1)
