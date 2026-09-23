import os
import tempfile
import zipfile
from pathlib import Path

from file_analyzer import analyze_file


# ============================================================
# CONFIGURATION
# ============================================================

MAX_ARCHIVE_SIZE = 500 * 1024 * 1024       # 500 MB uploaded ZIP
MAX_EXTRACTED_SIZE = 500 * 1024 * 1024     # 500 MB expanded
MAX_FILE_COUNT = 500
MAX_SINGLE_FILE_SIZE = 200 * 1024 * 1024   # 200 MB per file
MAX_NESTING_DEPTH = 1

SUPPORTED_PE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".cpl",
    ".ocx",
}


# ============================================================
# HELPERS
# ============================================================

def is_supported_pe_filename(filename):
    """
    Check whether a filename has an extension commonly
    associated with Windows PE files.
    """

    return (
        Path(filename).suffix.lower()
        in SUPPORTED_PE_EXTENSIONS
    )


def is_safe_archive_path(filename):
    """
    Prevent archive entries from escaping the extraction
    directory through absolute paths or '..' traversal.
    """

    path = Path(filename)

    if path.is_absolute():
        return False

    if path.drive:
        return False

    if ".." in path.parts:
        return False

    return True


def get_archive_file_type(filename):
    """
    Classify an archive entry by extension.
    """

    extension = Path(filename).suffix.lower()

    if extension in SUPPORTED_PE_EXTENSIONS:
        return "PE candidate"

    if extension == ".zip":
        return "Nested archive"

    return "Other"


# ============================================================
# ARCHIVE INSPECTION
# ============================================================

def inspect_archive(archive_path):
    """
    Inspect a ZIP without extracting or executing its contents.

    Returns metadata and a list of archive entries.
    """

    archive_size = os.path.getsize(
        archive_path
    )

    if archive_size > MAX_ARCHIVE_SIZE:
        raise ValueError(
            "Archive is too large. "
            "Maximum supported archive size is "
            f"{MAX_ARCHIVE_SIZE // (1024 * 1024)} MB."
        )

    if not zipfile.is_zipfile(
        archive_path
    ):
        raise ValueError(
            "The uploaded file is not a valid ZIP archive."
        )

    with zipfile.ZipFile(
        archive_path,
        "r"
    ) as archive:

        entries = archive.infolist()

        if len(entries) > MAX_FILE_COUNT:
            raise ValueError(
                "Archive contains too many files. "
                f"Maximum supported file count is "
                f"{MAX_FILE_COUNT}."
            )

        total_uncompressed_size = 0

        files = []
        directories = []
        unsafe_entries = []

        for entry in entries:
            filename = entry.filename

            if not is_safe_archive_path(
                filename
            ):
                unsafe_entries.append(
                    filename
                )
                continue

            if entry.is_dir():
                directories.append(
                    filename
                )
                continue

            total_uncompressed_size += (
                entry.file_size
            )

            if (
                entry.file_size
                > MAX_SINGLE_FILE_SIZE
            ):
                raise ValueError(
                    "Archive contains a file that is "
                    "too large to analyze."
                )

            files.append({
                "name": filename,
                "size": entry.file_size,
                "compressed_size":
                    entry.compress_size,
                "type":
                    get_archive_file_type(filename),
            })

        if (
            total_uncompressed_size
            > MAX_EXTRACTED_SIZE
        ):
            raise ValueError(
                "Archive would expand beyond the "
                f"{MAX_EXTRACTED_SIZE // (1024 * 1024)} MB "
                "extraction limit."
            )

    return {
        "archive_size": archive_size,
        "file_count": len(files),
        "directory_count": len(directories),
        "total_uncompressed_size":
            total_uncompressed_size,
        "files": files,
        "unsafe_entries": unsafe_entries,
    }


# ============================================================
# SAFE EXTRACTION
# ============================================================

def extract_archive(
    archive_path,
    destination
):
    """
    Safely extract a ZIP archive.

    Files are written individually after validating their
    paths rather than relying on unrestricted extraction.
    """

    extracted_files = []

    with zipfile.ZipFile(
        archive_path,
        "r"
    ) as archive:

        for entry in archive.infolist():

            if entry.is_dir():
                continue

            filename = entry.filename

            if not is_safe_archive_path(
                filename
            ):
                continue

            destination_path = (
                Path(destination)
                / filename
            )

            destination_path.parent.mkdir(
                parents=True,
                exist_ok=True
            )

            with archive.open(
                entry,
                "r"
            ) as source:

                with open(
                    destination_path,
                    "wb"
                ) as target:

                    while True:
                        chunk = source.read(
                            1024 * 1024
                        )

                        if not chunk:
                            break

                        target.write(
                            chunk
                        )

            extracted_files.append(
                str(destination_path)
            )

    return extracted_files


# ============================================================
# PE DISCOVERY
# ============================================================

def find_pe_candidates(
    extracted_files
):
    """
    Find files that are candidates for PE analysis.
    """

    candidates = []

    for file_path in extracted_files:

        if is_supported_pe_filename(
            file_path
        ):
            candidates.append(
                file_path
            )

    return candidates


# ============================================================
# ARCHIVE ANALYSIS
# ============================================================

def analyze_archive(
    archive_path,
    display_name=None,
    nesting_depth=0
):
    """
    Analyze a ZIP archive and statically analyze PE files
    contained within it.

    Nothing from the archive is executed.
    """

    archive_info = inspect_archive(
        archive_path
    )

    if nesting_depth > MAX_NESTING_DEPTH:
        raise ValueError(
            "Maximum archive nesting depth exceeded."
        )

    with tempfile.TemporaryDirectory(
        prefix="iocyra_archive_"
    ) as extraction_directory:

        extracted_files = extract_archive(
            archive_path,
            extraction_directory
        )

        pe_candidates = find_pe_candidates(
            extracted_files
        )

        file_results = []
        skipped_files = []

        for extracted_file in extracted_files:

            relative_path = os.path.relpath(
                extracted_file,
                extraction_directory
            )

            if extracted_file in pe_candidates:

                try:
                    result = analyze_file(
                        extracted_file
                    )

                    result["file"]["name"] = (
                        relative_path
                    )

                    file_results.append(
                        result
                    )

                except Exception as error:
                    file_results.append({
                        "file": {
                            "name": relative_path
                        },
                        "error":
                            "Analysis failed."
                    })

            else:
                skipped_files.append(
                    relative_path
                )

        return {
            "archive": {
                "name":
                    display_name
                    or os.path.basename(
                        archive_path
                    ),

                "size":
                    archive_info["archive_size"],

                "file_count":
                    archive_info["file_count"],

                "directory_count":
                    archive_info["directory_count"],

                "total_uncompressed_size":
                    archive_info[
                        "total_uncompressed_size"
                    ],

                "unsafe_entries":
                    archive_info[
                        "unsafe_entries"
                    ],
            },

            "files": file_results,

            "skipped_files":
                skipped_files,

            "summary": {
                "analyzed":
                    len(file_results),

                "skipped":
                    len(skipped_files),

                "unsafe":
                    len(
                        archive_info[
                            "unsafe_entries"
                        ]
                    ),
            },
        }


# ============================================================
# TEST / DEBUG
# ============================================================

def print_archive_report(result):
    """
    Print a human-readable archive analysis report.
    """

    archive = result["archive"]
    files = result["files"]
    skipped = result["skipped_files"]
    summary = result["summary"]

    print(
        "=== IOCYRA Archive Analysis ==="
    )

    print(
        "Archive:",
        archive["name"]
    )

    print(
        "Size:",
        archive["size"],
        "bytes"
    )

    print(
        "Files:",
        archive["file_count"]
    )

    print(
        "Directories:",
        archive["directory_count"]
    )

    print(
        "Uncompressed size:",
        archive[
            "total_uncompressed_size"
        ],
        "bytes"
    )

    print()

    print(
        "Analyzed:",
        summary["analyzed"]
    )

    print(
        "Skipped:",
        summary["skipped"]
    )

    print(
        "Unsafe:",
        summary["unsafe"]
    )

    print()

    if archive["unsafe_entries"]:
        print(
            "=== Unsafe Entries ==="
        )

        for filename in archive[
            "unsafe_entries"
        ]:
            print(
                f"  - {filename}"
            )

        print()

    print(
        "=== Analyzed Files ==="
    )

    if not files:
        print(
            "No supported PE files found."
        )

    else:
        for result in files:

            file_info = result["file"]

            print()

            print(
                file_info["name"]
            )

            if "error" in result:
                print(
                    "  Analysis failed."
                )
                continue

            triage = result["triage"]

            print(
                "  Triage:",
                triage["level"]
            )

            print(
                "  Score:",
                triage["score"]
            )

            print(
                "  SHA-256:",
                file_info["sha256"]
            )

    print()

    print(
        "=== Skipped Files ==="
    )

    if not skipped:
        print(
            "None."
        )

    else:
        for filename in skipped[:100]:
            print(
                f"  - {filename}"
            )

        if len(skipped) > 100:
            print(
                f"  ... and "
                f"{len(skipped) - 100} more"
            )


if __name__ == "__main__":

    archive_path = "sample.zip"

    result = analyze_archive(
        archive_path
    )

    print_archive_report(
        result
    )