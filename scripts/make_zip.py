"""ThreatLens AI - Submission Packager Script.

Packages all required project modules, data, outputs, reports, documentation,
and tests into ThreatLens-AI-Submission.zip while strictly excluding
virtual environments (.venv), caches (__pycache__, .pytest_cache),
sensitive credentials (.env), and operating system temporary files.
"""

from pathlib import Path
import sys
import zipfile

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent

ZIP_OUTPUT_PATH = PROJECT_ROOT / "ThreatLens-AI-Submission.zip"

# Strict inclusion manifest (relative to PROJECT_ROOT)
INCLUDE_ITEMS = [
    "src",
    "tests",
    "scripts",
    "docs",
    "reports",
    "outputs",
    "data/traffic.csv",
    "data/sample_input.json",
    "app.py",
    "README.md",
    "requirements.txt",
    ".env.example",
    ".gitignore",
    "pytest.ini",
]

# Strict exclusions
EXCLUDE_DIR_NAMES = {
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".git",
    ".idea",
    ".vscode",
}

EXCLUDE_FILE_PATTERNS = {
    ".env",
    "ThreatLens-AI-Submission.zip",
    "Thumbs.db",
    ".DS_Store",
}


def should_exclude(file_path: Path) -> bool:
    """Check if a file should be excluded from submission archive."""
    # Check directory components
    for part in file_path.parts:
        if part in EXCLUDE_DIR_NAMES:
            return True
        if part.endswith(".egg-info"):
            return True

    # Check filename
    name = file_path.name
    if name in EXCLUDE_FILE_PATTERNS:
        return True
    if name.endswith((".pyc", ".pyo", ".tmp")):
        return True

    return False


def create_submission_zip() -> Path:
    """Create the submission zip archive and print file listing."""
    print("=" * 70)
    print("THREATLENS AI: Packaging Submission Archive")
    print(f"Target Archive: {ZIP_OUTPUT_PATH}")
    print("=" * 70)

    # Remove prior zip if exists
    if ZIP_OUTPUT_PATH.exists():
        ZIP_OUTPUT_PATH.unlink()

    total_files = 0
    total_uncompressed_bytes = 0

    with zipfile.ZipFile(ZIP_OUTPUT_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for item_rel in INCLUDE_ITEMS:
            item_path = PROJECT_ROOT / item_rel
            if not item_path.exists():
                print(f"Warning: Item {item_rel} does not exist. Skipping.")
                continue

            if item_path.is_file():
                if not should_exclude(item_path):
                    arcname = f"ThreatLens-AI/{item_rel}"
                    zf.write(item_path, arcname=arcname)
                    total_files += 1
                    total_uncompressed_bytes += item_path.stat().st_size
                    print(f"  + {arcname}")
            elif item_path.is_dir():
                for file_path in sorted(item_path.rglob("*")):
                    if file_path.is_file() and not should_exclude(file_path):
                        rel_path = file_path.relative_to(PROJECT_ROOT).as_posix()
                        arcname = f"ThreatLens-AI/{rel_path}"
                        zf.write(file_path, arcname=arcname)
                        total_files += 1
                        total_uncompressed_bytes += file_path.stat().st_size
                        print(f"  + {arcname}")

    zip_size_bytes = ZIP_OUTPUT_PATH.stat().st_size
    print("\n" + "-" * 70)
    print("PACKAGING SUMMARY:")
    print(f"  Files packaged:         {total_files}")
    print(f"  Uncompressed Size:      {total_uncompressed_bytes / (1024*1024):.2f} MB ({total_uncompressed_bytes:,} bytes)")
    print(f"  Compressed ZIP Size:    {zip_size_bytes / (1024*1024):.2f} MB ({zip_size_bytes:,} bytes)")
    print(f"  Archive location:       {ZIP_OUTPUT_PATH}")
    print("-" * 70)

    # Verify exclusions in zip
    with zipfile.ZipFile(ZIP_OUTPUT_PATH, "r") as zf:
        for member in zf.namelist():
            for forbidden in [".venv", "__pycache__", ".pytest_cache", ".env/"]:
                if forbidden in member:
                    raise ValueError(f"Exclusion violation! Found '{forbidden}' in archive member: {member}")
            if member == "ThreatLens-AI/.env":
                raise ValueError("Exclusion violation! .env file was packaged into archive.")

    print("[ACCEPTANCE CHECK] Exclusions verified: No .venv, __pycache__, .env, or temp files.")
    print("=" * 70)
    return ZIP_OUTPUT_PATH


def main() -> None:
    try:
        create_submission_zip()
    except Exception as e:
        print(f"ERROR: Packaging failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

