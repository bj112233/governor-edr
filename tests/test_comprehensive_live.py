#!/usr/bin/env python3
"""Comprehensive live test — 10+ files across all formats + OCR."""

import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from skills.file_analyst.scripts.file_analyst import (
    analyze_contract,
    analyze_datasheet,
    analyze_with_profile,
    chart_csv,
    extract_pdf_tables,
    file_integrity_check,
    ocr_image,
    ocr_pdf_force,
    ocr_translate_image,
    read_csv,
    read_docx,
    read_json,
    read_pdf,
    read_txt,
    read_xlsx,
    redact_pdf,
    smart_summarize,
    xlsx_integrity,
)

DOWNLOADS = os.path.join(project_root, "downloads")
TEST_FIXTURES = os.path.join(project_root, "tests", "output")

TEST_FILES = [
    ("PDF Hebrew contract", "sample_contract.pdf", read_pdf, {"pages": 3}),
    ("PDF Hebrew lease", "חוזה שכירות.pdf", read_pdf, {"pages": 3}),
    ("PDF insurance", "מפרט פוליסה.pdf", read_pdf, {"pages": 3}),
    ("PDF audio report", "ניתוח דוח מערכת אודיו הנדסי.pdf", read_pdf, {"pages": 3}),
    ("PDF Arabic stories", "ערבית_מדוברת_סיפורים_קצרים_נואל_–_ויקיספר.pdf", read_pdf, {"pages": 2}),
    ("XLSX", "לחמנינה מפעל_תפוז טרי.xlsx", read_xlsx, {}),
    ("PNG OCR test", os.path.join(TEST_FIXTURES, "test_ocr_image.png"), ocr_image, {"lang": "eng"}),
    ("TXT test", None, read_txt, {"create_test": True}),
    ("JSON test", None, read_json, {"create_test": True}),
    ("CSV test", None, read_csv, {"create_test": True}),
]


def run_test(name, filename, func, kwargs):
    """Run a single test and return result."""
    print(f"\n{'=' * 60}")
    print(f"TEST: {name}")
    print("=" * 60)

    # Create test files if needed
    if kwargs.pop("create_test", False):
        if func == read_txt:
            filename = os.path.join(DOWNLOADS, "test_live.txt")
            with open(filename, "w", encoding="utf-8") as f:
                f.write("Hello world\nThis is a test file\nLine 3")
        elif func == read_json:
            import json as _json

            filename = os.path.join(DOWNLOADS, "test_live.json")
            with open(filename, "w", encoding="utf-8") as f:
                _json.dump({"key1": "value1", "key2": [1, 2, 3]}, f)
        elif func == read_csv:
            import csv as _csv

            filename = os.path.join(DOWNLOADS, "test_live.csv")
            with open(filename, "w", newline="", encoding="utf-8") as f:
                w = _csv.writer(f)
                w.writerow(["name", "value"])
                w.writerow(["A", "10"])
                w.writerow(["B", "20"])

    path = os.path.join(DOWNLOADS, filename) if filename else None
    if path and not os.path.exists(path):
        print(f"  ✗ File not found: {path}")
        return False, "missing"

    try:
        result = func(path, **kwargs)
        preview = str(result)[:150].replace("\n", " ")
        print(f"  ✓ Success ({len(str(result))} chars)")
        print(f"  Preview: {preview}...")

        # Check for errors
        if isinstance(result, str) and result.startswith("❌"):
            print(f"  ⚠️ Function returned error: {result[:200]}")
            return False, result[:100]

        return True, "ok"
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        import traceback

        traceback.print_exc()
        return False, f"exception: {e}"


def main():
    print("=" * 60)
    print("COMPREHENSIVE LIVE TEST — 10+ files across all formats")
    print("=" * 60)

    results = []
    for name, filename, func, kwargs in TEST_FILES:
        success, status = run_test(name, filename, func, kwargs)
        results.append((name, success, status))

    # Test OCR translate
    print(f"\n{'=' * 60}")
    print("TEST: OCR + Translate (PNG)")
    print("=" * 60)
    try:
        path = os.path.join(TEST_FIXTURES, "test_ocr_image.png")
        result = ocr_translate_image(path, target="he", lang="eng")
        if result and not result.startswith("❌"):
            print(f"  ✓ ocr_translate_image OK ({len(result)} chars)")
            results.append(("OCR translate", True, "ok"))
        else:
            print(f"  ⚠️ OCR translate: {result[:100]}")
            results.append(("OCR translate", False, "error"))
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        results.append(("OCR translate", False, str(e)))

    # Test analyze functions
    print(f"\n{'=' * 60}")
    print("TEST: smart_summarize")
    print("=" * 60)
    try:
        text = "Hello world.\n\nThis is paragraph 2.\n\nParagraph 3 here."
        result = smart_summarize(text, lines=2)
        if result and len(result) > 0:
            print(f"  ✓ smart_summarize OK ({len(result)} chars)")
            results.append(("smart_summarize", True, "ok"))
        else:
            results.append(("smart_summarize", False, "empty"))
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        results.append(("smart_summarize", False, str(e)))

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    passed = sum(1 for _, s, _ in results if s)
    for name, success, status in results:
        icon = "✓" if success else "✗"
        print(f"  {icon} {name}: {status}")

    print(f"\nOverall: {passed}/{len(results)} tests passed")
    return passed == len(results)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
