#!/usr/bin/env python3
"""Diagnose OCR setup and dependencies"""

import os
import shutil
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

print("=" * 60)
print("OCR DIAGNOSTICS")
print("=" * 60)

# 1. Check Python version
print(f"\n[1] Python: {sys.version}")
print(f"    Executable: {sys.executable}")

# 2. Check pdfplumber
print("\n[2] Checking pdfplumber...")
try:
    import pdfplumber

    print(f"    ✓ pdfplumber {pdfplumber.__version__} installed")
except ImportError as e:
    print(f"    ✗ pdfplumber NOT installed: {e}")

# 3. Check pdf2image
print("\n[3] Checking pdf2image...")
try:
    from pdf2image import convert_from_path

    print("    ✓ pdf2image installed")
except ImportError as e:
    print(f"    ✗ pdf2image NOT installed: {e}")

# 4. Check pytesseract
print("\n[4] Checking pytesseract...")
try:
    import pytesseract

    print("    ✓ pytesseract installed")
except ImportError as e:
    print(f"    ✗ pytesseract NOT installed: {e}")

# 5. Check Tesseract binary
print("\n[5] Checking Tesseract binary...")
tesseract_paths = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
    shutil.which("tesseract"),
]

found = False
for path in tesseract_paths:
    if path and os.path.isfile(path):
        print(f"    ✓ Tesseract found: {path}")
        found = True
        break

if not found:
    print("    ✗ Tesseract NOT found in any standard location")
    print("\n    To install Tesseract:")
    print("    1. Download from: https://github.com/UB-Mannheim/tesseract/wiki")
    print("    2. Run installer and select 'Hebrew' language pack")
    print("    3. Add to PATH or set TESSERACT_CMD environment variable")

# 6. Check Poppler (for pdf2image)
print("\n[6] Checking Poppler (for pdf2image)...")
poppler_paths = [
    r"C:\poppler\poppler-24.08.0\Library\bin",
    r"C:\Program Files\poppler\Library\bin",
]
found_poppler = False
for path in poppler_paths:
    if os.path.isdir(path) and os.path.isfile(os.path.join(path, "pdftoppm.exe")):
        print(f"    ✓ Poppler found: {path}")
        found_poppler = True
        break

if not found_poppler:
    print("    ⚠ Poppler NOT found (optional, pdf2image may still work)")
    print("    Download from: https://github.com/oschwartz10612/poppler-windows/releases")

# 7. Test full OCR pipeline (if all dependencies available)
if found:
    print("\n[7] Testing OCR pipeline...")
    from skills.file_analyst.scripts.file_analyst import _find_tesseract, _ocr_pdf

    tess = _find_tesseract()
    if tess:
        print(f"    ✓ _find_tesseract() returned: {tess}")
    else:
        print("    ✗ _find_tesseract() returned None")
else:
    print("\n[7] Skipping OCR pipeline test (Tesseract not found)")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
if not found:
    print("CRITICAL: Tesseract OCR binary is missing!")
    print("Install from: https://github.com/UB-Mannheim/tesseract/wiki")
    print("Then restart the bot.")
else:
    print("All OCR dependencies appear to be installed.")
