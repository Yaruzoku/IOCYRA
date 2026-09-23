import hashlib
import os
import re
from datetime import datetime, timezone


# ============================================================
# BASIC FILE ANALYSIS
# ============================================================

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            sha256.update(chunk)

    return sha256.hexdigest()


def get_file_size(file_path):
    return os.path.getsize(file_path)


def get_file_extension(file_path):
    return os.path.splitext(file_path)[1].lower()


# ============================================================
# PE FILE ANALYSIS
# ============================================================

def is_pe_file(file_path):
    with open(file_path, "rb") as file:
        signature = file.read(2)

        if signature != b"MZ":
            return False

        file.seek(0x3C)

        pe_offset = int.from_bytes(
            file.read(4),
            byteorder="little"
        )

        file.seek(pe_offset)

        pe_signature = file.read(4)

    return pe_signature == b"PE\0\0"


def get_pe_architecture(file_path):
    if not is_pe_file(file_path):
        return "Not a PE file"

    with open(file_path, "rb") as file:
        file.seek(0x3C)

        pe_offset = int.from_bytes(
            file.read(4),
            byteorder="little"
        )

        file.seek(pe_offset + 4)

        machine = int.from_bytes(
            file.read(2),
            byteorder="little"
        )

    if machine == 0x014C:
        return "x86 (32-bit)"

    elif machine == 0x8664:
        return "x64 (64-bit)"

    else:
        return f"Unknown (0x{machine:04X})"


def get_pe_entry_point(file_path):
    if not is_pe_file(file_path):
        return None

    with open(file_path, "rb") as file:
        file.seek(0x3C)

        pe_offset = int.from_bytes(
            file.read(4),
            byteorder="little"
        )

        optional_header_offset = pe_offset + 24

        file.seek(optional_header_offset + 16)

        entry_point = int.from_bytes(
            file.read(4),
            byteorder="little"
        )

    return f"0x{entry_point:08X}"


def get_pe_timestamp(file_path):
    if not is_pe_file(file_path):
        return None

    with open(file_path, "rb") as file:
        file.seek(0x3C)

        pe_offset = int.from_bytes(
            file.read(4),
            byteorder="little"
        )

        file.seek(pe_offset + 8)

        timestamp = int.from_bytes(
            file.read(4),
            byteorder="little"
        )

    return timestamp


def get_pe_section_count(file_path):
    if not is_pe_file(file_path):
        return None

    with open(file_path, "rb") as file:
        file.seek(0x3C)

        pe_offset = int.from_bytes(
            file.read(4),
            byteorder="little"
        )

        file.seek(pe_offset + 6)

        section_count = int.from_bytes(
            file.read(2),
            byteorder="little"
        )

    return section_count


def get_pe_sections(file_path):
    if not is_pe_file(file_path):
        return None

    with open(file_path, "rb") as file:
        file.seek(0x3C)

        pe_offset = int.from_bytes(
            file.read(4),
            byteorder="little"
        )

        file.seek(pe_offset + 6)

        section_count = int.from_bytes(
            file.read(2),
            byteorder="little"
        )

        file.seek(pe_offset + 20)

        optional_header_size = int.from_bytes(
            file.read(2),
            byteorder="little"
        )

        section_table_offset = (
            pe_offset
            + 24
            + optional_header_size
        )

        sections = []

        for i in range(section_count):
            file.seek(
                section_table_offset + (i * 40)
            )

            name = file.read(8).split(
                b"\0",
                1
            )[0].decode(
                "ascii",
                errors="replace"
            )

            sections.append(name)

    return sections


def get_pe_section_details(file_path):
    if not is_pe_file(file_path):
        return None

    with open(file_path, "rb") as file:
        file.seek(0x3C)

        pe_offset = int.from_bytes(
            file.read(4),
            byteorder="little"
        )

        file.seek(pe_offset + 6)

        section_count = int.from_bytes(
            file.read(2),
            byteorder="little"
        )

        file.seek(pe_offset + 20)

        optional_header_size = int.from_bytes(
            file.read(2),
            byteorder="little"
        )

        section_table_offset = (
            pe_offset
            + 24
            + optional_header_size
        )

        sections = []

        for i in range(section_count):
            file.seek(
                section_table_offset + (i * 40)
            )

            name = file.read(8).split(
                b"\0",
                1
            )[0].decode(
                "ascii",
                errors="replace"
            )

            virtual_size = int.from_bytes(
                file.read(4),
                byteorder="little"
            )

            virtual_address = int.from_bytes(
                file.read(4),
                byteorder="little"
            )

            raw_size = int.from_bytes(
                file.read(4),
                byteorder="little"
            )

            file.seek(
                section_table_offset
                + (i * 40)
                + 36
            )

            characteristics = int.from_bytes(
                file.read(4),
                byteorder="little"
            )

            permissions = decode_section_characteristics(
                characteristics
            )

            sections.append({
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "characteristics": characteristics,
                "permissions": permissions,
            })

    return sections


def get_pe_subsystem(file_path):
    if not is_pe_file(file_path):
        return None

    with open(file_path, "rb") as file:
        file.seek(0x3C)

        pe_offset = int.from_bytes(
            file.read(4),
            byteorder="little"
        )

        file.seek(pe_offset + 24 + 68)

        subsystem = int.from_bytes(
            file.read(2),
            byteorder="little"
        )

    if subsystem == 2:
        return "Windows GUI"

    elif subsystem == 3:
        return "Windows Console"

    elif subsystem == 9:
        return "Windows CE GUI"

    elif subsystem == 10:
        return "EFI Application"

    elif subsystem == 1:
        return "Native"

    else:
        return f"Unknown (0x{subsystem:04X})"


def decode_section_characteristics(characteristics):
    permissions = []

    if characteristics & 0x40000000:
        permissions.append("READ")

    if characteristics & 0x80000000:
        permissions.append("WRITE")

    if characteristics & 0x20000000:
        permissions.append("EXECUTE")

    return permissions


# ============================================================
# PE IMPORT DIRECTORY
# ============================================================

def get_pe_import_directory(file_path):
    if not is_pe_file(file_path):
        return None

    with open(file_path, "rb") as file:
        file.seek(0x3C)

        pe_offset = int.from_bytes(
            file.read(4),
            byteorder="little"
        )

        file.seek(pe_offset + 24)

        magic = int.from_bytes(
            file.read(2),
            byteorder="little"
        )

        if magic == 0x10B:
            data_directory_offset = (
                pe_offset + 24 + 96
            )

        elif magic == 0x20B:
            data_directory_offset = (
                pe_offset + 24 + 112
            )

        else:
            return None

        file.seek(data_directory_offset + 8)

        import_rva = int.from_bytes(
            file.read(4),
            byteorder="little"
        )

        import_size = int.from_bytes(
            file.read(4),
            byteorder="little"
        )

    return {
        "rva": f"0x{import_rva:08X}",
        "size": import_size,
    }


def rva_to_file_offset(file_path, rva):
    if not is_pe_file(file_path):
        return None

    with open(file_path, "rb") as file:
        file.seek(0x3C)

        pe_offset = int.from_bytes(
            file.read(4),
            byteorder="little"
        )

        file.seek(pe_offset + 6)

        section_count = int.from_bytes(
            file.read(2),
            byteorder="little"
        )

        file.seek(pe_offset + 20)

        optional_header_size = int.from_bytes(
            file.read(2),
            byteorder="little"
        )

        section_table_offset = (
            pe_offset
            + 24
            + optional_header_size
        )

        for i in range(section_count):
            section_offset = (
                section_table_offset
                + (i * 40)
            )

            file.seek(section_offset + 8)

            virtual_size = int.from_bytes(
                file.read(4),
                byteorder="little"
            )

            virtual_address = int.from_bytes(
                file.read(4),
                byteorder="little"
            )

            raw_size = int.from_bytes(
                file.read(4),
                byteorder="little"
            )

            raw_pointer = int.from_bytes(
                file.read(4),
                byteorder="little"
            )

            section_size = max(
                virtual_size,
                raw_size
            )

            if (
                virtual_address
                <= rva
                < virtual_address + section_size
            ):
                return raw_pointer + (
                    rva - virtual_address
                )

    return None


def get_pe_import_descriptors(file_path):
    if not is_pe_file(file_path):
        return None

    import_directory = get_pe_import_directory(
        file_path
    )

    if not import_directory:
        return None

    import_rva = int(
        import_directory["rva"],
        16
    )

    import_offset = rva_to_file_offset(
        file_path,
        import_rva
    )

    if import_offset is None:
        return None

    descriptors = []

    with open(file_path, "rb") as file:
        current_offset = import_offset

        while True:
            file.seek(current_offset)

            original_first_thunk = int.from_bytes(
                file.read(4),
                byteorder="little"
            )

            time_date_stamp = int.from_bytes(
                file.read(4),
                byteorder="little"
            )

            forwarder_chain = int.from_bytes(
                file.read(4),
                byteorder="little"
            )

            name_rva = int.from_bytes(
                file.read(4),
                byteorder="little"
            )

            first_thunk = int.from_bytes(
                file.read(4),
                byteorder="little"
            )

            if (
                original_first_thunk == 0
                and time_date_stamp == 0
                and forwarder_chain == 0
                and name_rva == 0
                and first_thunk == 0
            ):
                break

            descriptors.append({
                "original_first_thunk":
                    original_first_thunk,

                "time_date_stamp":
                    time_date_stamp,

                "forwarder_chain":
                    forwarder_chain,

                "name_rva":
                    name_rva,

                "first_thunk":
                    first_thunk,
            })

            current_offset += 20

    return descriptors


def read_pe_string(file, offset):
    file.seek(offset)

    data = bytearray()

    while True:
        byte = file.read(1)

        if not byte or byte == b"\0":
            break

        data.extend(byte)

    return data.decode(
        "ascii",
        errors="replace"
    )


# ============================================================
# PE IMPORT FUNCTIONS
# ============================================================

def get_pe_import_functions(file_path, descriptor):
    original_first_thunk = descriptor[
        "original_first_thunk"
    ]

    first_thunk = descriptor[
        "first_thunk"
    ]

    thunk_rva = (
        original_first_thunk
        if original_first_thunk != 0
        else first_thunk
    )

    if thunk_rva == 0:
        return []

    thunk_offset = rva_to_file_offset(
        file_path,
        thunk_rva
    )

    if thunk_offset is None:
        return []

    with open(file_path, "rb") as file:
        file.seek(0x3C)

        pe_offset = int.from_bytes(
            file.read(4),
            byteorder="little"
        )

        file.seek(pe_offset + 24)

        magic = int.from_bytes(
            file.read(2),
            byteorder="little"
        )

        if magic == 0x20B:
            thunk_size = 8
            ordinal_flag = 0x8000000000000000

        elif magic == 0x10B:
            thunk_size = 4
            ordinal_flag = 0x80000000

        else:
            return []

        functions = []

        current_offset = thunk_offset

        while True:
            file.seek(current_offset)

            thunk_data = file.read(
                thunk_size
            )

            if len(thunk_data) != thunk_size:
                break

            thunk_value = int.from_bytes(
                thunk_data,
                byteorder="little"
            )

            if thunk_value == 0:
                break

            if thunk_value & ordinal_flag:
                ordinal = thunk_value & 0xFFFF

                functions.append({
                    "name": None,
                    "ordinal": ordinal,
                    "import_type": "ordinal",
                })

            else:
                name_rva = thunk_value

                name_offset = rva_to_file_offset(
                    file_path,
                    name_rva
                )

                if name_offset is None:
                    break

                file.seek(name_offset)

                hint = int.from_bytes(
                    file.read(2),
                    byteorder="little"
                )

                name_data = bytearray()

                while True:
                    byte = file.read(1)

                    if not byte or byte == b"\0":
                        break

                    name_data.extend(byte)

                name = name_data.decode(
                    "ascii",
                    errors="replace"
                )

                functions.append({
                    "name": name,
                    "ordinal": None,
                    "hint": hint,
                    "import_type": "name",
                })

            current_offset += thunk_size

        return functions


def get_pe_imports(file_path):
    descriptors = get_pe_import_descriptors(
        file_path
    )

    if not descriptors:
        return []

    imports = []

    with open(file_path, "rb") as file:
        for descriptor in descriptors:
            name_rva = descriptor[
                "name_rva"
            ]

            name_offset = rva_to_file_offset(
                file_path,
                name_rva
            )

            if name_offset is None:
                continue

            dll_name = read_pe_string(
                file,
                name_offset
            )

            functions = get_pe_import_functions(
                file_path,
                descriptor
            )

            imports.append({
                "dll": dll_name,
                "functions": functions,
            })

    return imports


# ============================================================
# STRING EXTRACTION
# ============================================================

def extract_ascii_strings(
    file_path,
    minimum_length=4
):
    """
    Extract printable ASCII strings from the file.
    """

    strings = []

    with open(file_path, "rb") as file:
        data = file.read()

    current = bytearray()

    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)

        else:
            if len(current) >= minimum_length:
                strings.append(
                    current.decode(
                        "ascii",
                        errors="replace"
                    )
                )

            current.clear()

    if len(current) >= minimum_length:
        strings.append(
            current.decode(
                "ascii",
                errors="replace"
            )
        )

    return strings


def extract_utf16_strings(
    file_path,
    minimum_length=4
):
    """
    Extract printable UTF-16LE strings from the file.

    Windows PE files frequently store useful strings
    in UTF-16LE.
    """

    strings = []

    with open(file_path, "rb") as file:
        data = file.read()

    current = []

    index = 0

    while index + 1 < len(data):
        low = data[index]
        high = data[index + 1]

        if (
            32 <= low <= 126
            and high == 0
        ):
            current.append(
                chr(low)
            )

            index += 2
            continue

        if len(current) >= minimum_length:
            strings.append(
                "".join(current)
            )

        current.clear()
        index += 2

    if len(current) >= minimum_length:
        strings.append(
            "".join(current)
        )

    return strings


def extract_strings(
    file_path,
    minimum_length=4
):
    """
    Extract both ASCII and UTF-16LE strings.

    Duplicate strings are removed while preserving
    their original order.
    """

    ascii_strings = extract_ascii_strings(
        file_path,
        minimum_length
    )

    utf16_strings = extract_utf16_strings(
        file_path,
        minimum_length
    )

    strings = []
    seen = set()

    for value in ascii_strings + utf16_strings:
        if value not in seen:
            seen.add(value)
            strings.append(value)

    return strings


# ============================================================
# POWERSHELL ANALYSIS
# ============================================================

POWERSHELL_CONTEXT_PATTERNS = [
    r"(?i)\bpowershell(?:\.exe)?\b",
    r"(?i)(?<![A-Za-z0-9_.-])pwsh\.exe(?![A-Za-z0-9_.-])",
    r"(?i)\bSystem\.Management\.Automation\b",
]


POWERSHELL_BEHAVIOR_PATTERNS = {
    "PowerShell Download Activity": {
        "patterns": [
            r"(?i)\bDownloadString\b",
            r"(?i)\bDownloadFile\b",
            r"(?i)\bInvoke-WebRequest\b",
            r"(?i)\bInvoke-RestMethod\b",
            r"(?i)\biwr\b",
            r"(?i)\birm\b",
        ],
        "confidence": "MEDIUM",
        "description":
            "Contains PowerShell commands or .NET methods commonly used to retrieve data.",
    },

    "PowerShell Dynamic Execution": {
        "patterns": [
            r"(?i)\bInvoke-Expression\b",
            r"(?i)\bFromBase64String\b",
        ],
        "confidence": "MEDIUM",
        "description":
            "Contains constructs commonly associated with dynamic PowerShell command or encoded-data execution.",
    },

    "PowerShell Obfuscation": {
        "patterns": [
            r"(?i)\[char\]\s*\d+",
            r"(?i)\[convert\]::FromBase64String",
            r"(?i)\bString\.Replace\s*\(",
            r"(?i)-join\s*\(",
        ],
        "confidence": "MEDIUM",
        "description":
            "Contains patterns that may be used to construct or obscure PowerShell commands.",
    },
}


POWERSHELL_CONTEXT_SWITCH_PATTERNS = {
    "Encoded PowerShell": [
        r"(?i)(?:^|\s)-enc(?:odedcommand)?(?:\s|$)",
        r"(?i)(?:^|\s)/enc(?:odedcommand)?(?:\s|$)",
    ],

    "PowerShell Execution Policy Bypass": [
        r"(?i)-executionpolicy\s+bypass",
        r"(?i)-ep\s+bypass",
        r"(?i)/executionpolicy\s+bypass",
        r"(?i)/ep\s+bypass",
    ],

    "Hidden PowerShell Window": [
        r"(?i)-windowstyle\s+hidden",
        r"(?i)-w\s+hidden",
        r"(?i)/windowstyle\s+hidden",
        r"(?i)/w\s+hidden",
    ],

    "PowerShell No Profile": [
        r"(?i)(?:^|\s)-noprofile(?:\s|$)",
        r"(?i)(?:^|\s)-nop(?:\s|$)",
    ],

    "PowerShell Command Execution": [
        r"(?i)(?:^|\s)-command(?:\s|$)",
        r"(?i)(?:^|\s)/command(?:\s|$)",
    ],

    "PowerShell Script Execution": [
        r"(?i)(?:^|\s)-file(?:\s|$)",
        r"(?i)(?:^|\s)/file(?:\s|$)",
    ],
}


def contains_powershell_context(string):
    """
    Determine whether a string contains strong evidence that
    the string is referring to PowerShell.

    Generic switches such as -c and -f intentionally do not
    count as PowerShell context.
    """

    for pattern in POWERSHELL_CONTEXT_PATTERNS:
        if re.search(pattern, string):
            return True

    return False


def analyze_powershell(strings):
    """
    Analyze extracted strings for PowerShell-related indicators.

    The engine is intentionally conservative:

    - PowerShell executable/framework references are LOW.
    - Generic switches are ignored unless PowerShell context
      exists in the same string.
    - Strong PowerShell behavior receives MEDIUM confidence.
    - IEX is intentionally not treated as a standalone indicator.
    """

    findings = []

    context_strings = [
        string
        for string in strings
        if contains_powershell_context(string)
    ]

    # --------------------------------------------------------
    # PowerShell executable / framework context
    # --------------------------------------------------------

    executable_matches = []

    for string in context_strings:
        if re.search(
            r"(?i)\bpowershell(?:\.exe)?\b",
            string
        ):
            executable_matches.append(string)

        elif re.search(
            r"(?i)(?<![A-Za-z0-9_.-])pwsh\.exe(?![A-Za-z0-9_.-])",
            string
        ):
            executable_matches.append(string)

    automation_matches = [
        string
        for string in context_strings
        if re.search(
            r"(?i)\bSystem\.Management\.Automation\b",
            string
        )
    ]

    if executable_matches:
        findings.append({
            "category": "PowerShell Executable",
            "confidence": "LOW",
            "description":
                "References a PowerShell executable.",
            "matches": sorted(
                set(executable_matches)
            ),
        })

    if automation_matches:
        findings.append({
            "category": "PowerShell Automation",
            "confidence": "LOW",
            "description":
                "References the .NET PowerShell automation framework.",
            "matches": sorted(
                set(automation_matches)
            ),
        })

    # --------------------------------------------------------
    # Strong PowerShell behavior
    # --------------------------------------------------------

    for category, data in POWERSHELL_BEHAVIOR_PATTERNS.items():
        matched_strings = []

        for string in strings:
            for pattern in data["patterns"]:
                if re.search(pattern, string):
                    matched_strings.append(string)
                    break

        if not matched_strings:
            continue

        findings.append({
            "category": category,
            "confidence": data["confidence"],
            "description": data["description"],
            "matches": sorted(
                set(matched_strings)
            ),
        })

    # --------------------------------------------------------
    # PowerShell switches
    #
    # Only analyze these when the SAME STRING contains
    # PowerShell context.
    # --------------------------------------------------------

    if context_strings:
        for category, patterns in POWERSHELL_CONTEXT_SWITCH_PATTERNS.items():
            matched_strings = []

            for string in context_strings:
                for pattern in patterns:
                    if re.search(pattern, string):
                        matched_strings.append(string)
                        break

            if not matched_strings:
                continue

            findings.append({
                "category": category,
                "confidence": "MEDIUM",
                "description":
                    get_powershell_switch_description(
                        category
                    ),
                "matches": sorted(
                    set(matched_strings)
                ),
            })

    # --------------------------------------------------------
    # Overall confidence
    # --------------------------------------------------------

    medium_categories = {
        finding["category"]
        for finding in findings
        if finding["confidence"] == "MEDIUM"
    }

    strong_behavior_categories = {
        "PowerShell Download Activity",
        "PowerShell Dynamic Execution",
        "PowerShell Obfuscation",
        "Encoded PowerShell",
        "PowerShell Execution Policy Bypass",
        "Hidden PowerShell Window",
    }

    strong_behavior_count = len(
        medium_categories.intersection(
            strong_behavior_categories
        )
    )

    overall_confidence = "LOW"

    if strong_behavior_count >= 2:
        overall_confidence = "HIGH"

    elif strong_behavior_count >= 1:
        overall_confidence = "MEDIUM"

    elif any(
        finding["confidence"] == "MEDIUM"
        for finding in findings
    ):
        overall_confidence = "MEDIUM"

    return findings


def get_powershell_switch_description(category):
    descriptions = {
        "Encoded PowerShell":
            "Contains a PowerShell encoded-command option.",

        "PowerShell Execution Policy Bypass":
            "Contains a PowerShell execution-policy bypass option.",

        "Hidden PowerShell Window":
            "Contains an option associated with hiding a PowerShell window.",

        "PowerShell No Profile":
            "Contains an option that starts PowerShell without the user profile.",

        "PowerShell Command Execution":
            "Contains an explicit PowerShell command-execution option.",

        "PowerShell Script Execution":
            "Contains an explicit PowerShell script-file execution option.",
    }

    return descriptions.get(
        category,
        "Contains a PowerShell command-line option."
    )


def get_powershell_summary(powershell_findings):
    """
    Convert PowerShell findings into an overall confidence level.

    LOW:
        Only PowerShell executable/framework references.

    MEDIUM:
        At least one meaningful PowerShell behavior.

    HIGH:
        Multiple strong PowerShell behaviors are present.
    """

    if not powershell_findings:
        return None

    strong_categories = {
        "PowerShell Download Activity",
        "PowerShell Dynamic Execution",
        "PowerShell Obfuscation",
        "Encoded PowerShell",
        "PowerShell Execution Policy Bypass",
        "Hidden PowerShell Window",
    }

    strong_behavior_count = sum(
        1
        for finding in powershell_findings
        if finding["category"] in strong_categories
    )

    if strong_behavior_count >= 2:
        confidence = "HIGH"

    elif strong_behavior_count >= 1:
        confidence = "MEDIUM"

    else:
        confidence = "LOW"

    return {
        "category": "PowerShell",
        "confidence": confidence,
        "findings": powershell_findings,
    }


# ============================================================
# API BEHAVIOR INDICATORS
# ============================================================

API_INDICATORS = {
    "Process Discovery": {
        "description":
            "Enumerates or inspects running processes.",

        "apis": {
            "CreateToolhelp32Snapshot",
            "Process32FirstW",
            "Process32NextW",
            "K32EnumProcesses",
            "K32EnumProcessModules",
            "K32GetModuleFileNameExW",
            "QueryFullProcessImageNameW",
        },
    },

    "Process Manipulation": {
        "description":
            "Opens, creates, terminates, or otherwise interacts with processes.",

        "apis": {
            "OpenProcess",
            "CreateProcessW",
            "CreateProcessA",
            "TerminateProcess",
            "GetExitCodeProcess",
        },
    },

    "Dynamic API Resolution": {
        "description":
            "Loads DLLs or resolves API addresses dynamically.",

        "apis": {
            "LoadLibraryA",
            "LoadLibraryW",
            "LoadLibraryExA",
            "LoadLibraryExW",
            "GetProcAddress",
            "FreeLibrary",
        },
    },

    "Memory Protection": {
        "description":
            "Allocates memory or changes memory protection attributes.",

        "apis": {
            "VirtualProtect",
            "VirtualProtectEx",
            "VirtualAlloc",
            "VirtualAllocEx",
            "VirtualFree",
            "VirtualFreeEx",
            "WriteProcessMemory",
            "ReadProcessMemory",
        },
    },

    "Anti-Debugging": {
        "description":
            "Contains APIs commonly associated with debugger detection.",

        "apis": {
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "OutputDebugStringA",
            "OutputDebugStringW",
        },
    },

    "File Manipulation": {
        "description":
            "Creates, modifies, deletes, or enumerates files.",

        "apis": {
            "CreateFileA",
            "CreateFileW",
            "WriteFile",
            "ReadFile",
            "DeleteFileA",
            "DeleteFileW",
            "MoveFileA",
            "MoveFileW",
            "CopyFileA",
            "CopyFileW",
            "FindFirstFileA",
            "FindFirstFileW",
            "FindFirstFileExA",
            "FindFirstFileExW",
            "FindNextFileA",
            "FindNextFileW",
            "CreateDirectoryA",
            "CreateDirectoryW",
            "RemoveDirectoryA",
            "RemoveDirectoryW",
        },
    },

    "Service / Persistence": {
        "description":
            "Contains APIs associated with Windows service installation or configuration.",

        "apis": {
            "OpenSCManagerA",
            "OpenSCManagerW",
            "CreateServiceA",
            "CreateServiceW",
            "OpenServiceA",
            "OpenServiceW",
            "StartServiceA",
            "StartServiceW",
            "DeleteService",
            "ChangeServiceConfigA",
            "ChangeServiceConfigW",
        },
    },

    "Registry Access": {
        "description":
            "Accesses or modifies the Windows Registry.",

        "apis": {
            "RegOpenKeyA",
            "RegOpenKeyW",
            "RegOpenKeyExA",
            "RegOpenKeyExW",
            "RegCreateKeyA",
            "RegCreateKeyW",
            "RegCreateKeyExA",
            "RegCreateKeyExW",
            "RegSetValueA",
            "RegSetValueW",
            "RegSetValueExA",
            "RegSetValueExW",
            "RegDeleteKeyA",
            "RegDeleteKeyW",
            "RegDeleteValueA",
            "RegDeleteValueW",
        },
    },

    "Security Token Access": {
        "description":
            "Accesses Windows process or security token information.",

        "apis": {
            "OpenProcessToken",
            "OpenThreadToken",
            "GetTokenInformation",
            "DuplicateToken",
            "DuplicateTokenEx",
        },
    },

    "Privilege Manipulation": {
        "description":
            "Contains APIs capable of modifying process privileges.",

        "apis": {
            "AdjustTokenPrivileges",
            "LookupPrivilegeValueA",
            "LookupPrivilegeValueW",
            "SetTokenInformation",
        },
    },

    "Network Communication": {
        "description":
            "Contains APIs commonly used for network communication.",

        "apis": {
            "InternetOpenA",
            "InternetOpenW",
            "InternetOpenUrlA",
            "InternetOpenUrlW",
            "InternetConnectA",
            "InternetConnectW",
            "HttpOpenRequestA",
            "HttpOpenRequestW",
            "HttpSendRequestA",
            "HttpSendRequestW",
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpOpenRequest",
            "WinHttpSendRequest",
            "WinHttpReceiveResponse",
            "WSAStartup",
            "socket",
            "connect",
            "send",
            "recv",
        },
    },

    "Command / Shell Execution": {
        "description":
            "Contains APIs specifically associated with shell or command execution.",

        "apis": {
            "WinExec",
            "ShellExecuteA",
            "ShellExecuteW",
            "ShellExecuteExA",
            "ShellExecuteExW",
            "system",
        },
    },

    "Environment Discovery": {
        "description":
            "Queries environment, system, drive, or host information.",

        "apis": {
            "GetEnvironmentVariableA",
            "GetEnvironmentVariableW",
            "GetEnvironmentStringsA",
            "GetEnvironmentStringsW",
            "ExpandEnvironmentStringsA",
            "ExpandEnvironmentStringsW",
            "GetComputerNameA",
            "GetComputerNameW",
            "GetUserNameA",
            "GetUserNameW",
            "GetSystemInfo",
            "GetNativeSystemInfo",
            "GetSystemMetrics",
            "GetDriveTypeA",
            "GetDriveTypeW",
        },
    },

    "Timing / Sleep": {
        "description":
            "Uses timing or sleep-related APIs. These are common in legitimate software and are weak indicators by themselves.",

        "apis": {
            "QueryPerformanceCounter",
            "QueryPerformanceFrequency",
            "GetTickCount",
            "GetTickCount64",
            "Sleep",
            "SleepEx",
        },
    },
}


# ============================================================
# BEHAVIORAL COMBINATIONS
# ============================================================

BEHAVIOR_COMBINATIONS = [
    {
        "name": "Process Injection",
        "description":
            "Uses a combination of process access, remote memory manipulation, and process memory writing.",

        "required_groups": [
            {
                "OpenProcess",
            },
            {
                "VirtualAllocEx",
                "VirtualProtectEx",
            },
            {
                "WriteProcessMemory",
            },
        ],

        "confidence": "HIGH",
        "score": 6,
    },

    {
        "name": "Service Persistence",
        "description":
            "Combines service-manager access with service creation and startup APIs.",

        "required_groups": [
            {
                "OpenSCManagerA",
                "OpenSCManagerW",
            },
            {
                "CreateServiceA",
                "CreateServiceW",
            },
            {
                "StartServiceA",
                "StartServiceW",
            },
        ],

        "confidence": "HIGH",
        "score": 6,
    },

    {
        "name": "Privilege Manipulation",
        "description":
            "Accesses a security token and contains an API capable of modifying token privileges.",

        "required_groups": [
            {
                "OpenProcessToken",
                "OpenThreadToken",
            },
            {
                "AdjustTokenPrivileges",
            },
        ],

        "confidence": "MEDIUM",
        "score": 3,
    },

    {
        "name": "Debugger Detection",
        "description":
            "Contains multiple APIs associated with debugger detection or analysis resistance.",

        "required_groups": [
            {
                "IsDebuggerPresent",
                "CheckRemoteDebuggerPresent",
            },
        ],

        "minimum_matches": 2,
        "confidence": "MEDIUM",
        "score": 2,
    },
]


# ============================================================
# API ANALYSIS HELPERS
# ============================================================

def get_imported_api_names(imports):
    """
    Return a set containing all named imported APIs.
    """

    imported_functions = set()

    for import_entry in imports:
        for function in import_entry["functions"]:
            if function["import_type"] == "name":
                imported_functions.add(
                    function["name"]
                )

    return imported_functions


def get_category_confidence(category, matched_apis):
    """
    Estimate how meaningful a category is.

    Common Windows APIs remain LOW. Stronger combinations
    are handled separately by the behavioral engine.
    """

    match_count = len(matched_apis)

    if category == "Process Discovery":
        return "LOW"

    if category == "Process Manipulation":
        return "LOW"

    if category == "Dynamic API Resolution":
        return "LOW"

    if category == "Memory Protection":
        suspicious_apis = {
            "VirtualAllocEx",
            "VirtualProtectEx",
            "WriteProcessMemory",
            "ReadProcessMemory",
        }

        if len(
            suspicious_apis.intersection(matched_apis)
        ) >= 2:
            return "MEDIUM"

        return "LOW"

    if category == "Anti-Debugging":
        if match_count >= 2:
            return "MEDIUM"

        return "LOW"

    if category == "Service / Persistence":
        return "LOW"

    if category == "Registry Access":
        return "LOW"

    if category == "Security Token Access":
        return "LOW"

    if category == "Privilege Manipulation":
        if "AdjustTokenPrivileges" in matched_apis:
            return "MEDIUM"

        return "LOW"

    if category == "Network Communication":
        return "LOW"

    if category == "Command / Shell Execution":
        return "MEDIUM"

    if category == "Environment Discovery":
        return "LOW"

    if category == "Timing / Sleep":
        return "LOW"

    return "LOW"


def get_confidence_weight(confidence):
    """
    Convert confidence into a conservative triage weight.

    LOW indicators do not increase the overall score.
    """

    if confidence == "HIGH":
        return 3

    if confidence == "MEDIUM":
        return 1

    return 0


# ============================================================
# API ANALYSIS
# ============================================================

def analyze_imports(imports):
    """
    Analyze imported APIs and return categorized
    behavioral indicators.
    """

    imported_functions = get_imported_api_names(
        imports
    )

    indicators = []

    for category, data in API_INDICATORS.items():
        matched_apis = sorted(
            api
            for api in data["apis"]
            if api in imported_functions
        )

        if not matched_apis:
            continue

        confidence = get_category_confidence(
            category,
            matched_apis
        )

        indicators.append({
            "category": category,
            "confidence": confidence,
            "description": data["description"],
            "apis": matched_apis,
            "score": get_confidence_weight(
                confidence
            ),
        })

    return indicators


def analyze_behavior_combinations(
    imported_functions,
    powershell_summary=None
):
    """
    Look for behavior combinations that are more meaningful
    than individual imports.
    """

    behaviors = []

    for behavior in BEHAVIOR_COMBINATIONS:
        required_groups = behavior.get(
            "required_groups",
            []
        )

        all_groups_present = True
        matched_apis = set()

        for api_group in required_groups:
            group_matches = (
                api_group
                & imported_functions
            )

            if not group_matches:
                all_groups_present = False
                break

            matched_apis.update(
                group_matches
            )

        if not all_groups_present:
            continue

        minimum_matches = behavior.get(
            "minimum_matches"
        )

        if minimum_matches is not None:
            if len(matched_apis) < minimum_matches:
                continue

        behaviors.append({
            "category": behavior["name"],
            "confidence": behavior["confidence"],
            "description": behavior["description"],
            "apis": sorted(matched_apis),
            "score": behavior["score"],
        })

    return behaviors


# ============================================================
# TRIAGE SCORING
# ============================================================

def calculate_indicator_score(
    indicators,
    combinations=None,
    powershell_summary=None
):
    """
    Calculate a conservative static-analysis score.

    Individual LOW indicators contribute zero.
    MEDIUM indicators contribute one.
    HIGH indicators contribute three.

    Behavioral combinations receive additional weight.

    PowerShell contributes separately:
        LOW    = 0
        MEDIUM = 1
        HIGH   = 3
    """

    score = sum(
        indicator.get("score", 0)
        for indicator in indicators
    )

    if combinations:
        score += sum(
            combination.get("score", 0)
            for combination in combinations
        )

    if powershell_summary:
        confidence = powershell_summary["confidence"]

        if confidence == "HIGH":
            score += 3

        elif confidence == "MEDIUM":
            score += 1

    return score


def get_triage_level(
    score,
    combinations=None,
    powershell_summary=None
):
    """
    Convert the static-analysis score into a triage
    classification.

    HIGH is primarily driven by strong behavioral
    combinations or high-confidence PowerShell findings.
    """

    combinations = combinations or []

    high_confidence = sum(
        1
        for combination in combinations
        if combination["confidence"] == "HIGH"
    )

    medium_confidence = sum(
        1
        for combination in combinations
        if combination["confidence"] == "MEDIUM"
    )

    if high_confidence >= 1:
        return "HIGH"

    if powershell_summary:
        if powershell_summary["confidence"] == "HIGH":
            return "HIGH"

    if score >= 6:
        return "REVIEW"

    if medium_confidence >= 2:
        return "REVIEW"

    if score >= 2:
        return "LOW"

    if medium_confidence >= 1:
        return "LOW"

    return "MINIMAL"


# ============================================================
# TIMESTAMP FORMATTING
# ============================================================

def format_pe_timestamp(timestamp):
    if timestamp is None:
        return None

    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc
    ).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


# ============================================================
# COMPLETE FILE ANALYSIS PIPELINE
# ============================================================

def analyze_file(file_path):
    """
    Run the complete static file analysis pipeline.

    Returns structured analysis data for IOCYRA.
    """

    # --------------------------------------------------------
    # Basic file information
    # --------------------------------------------------------

    file_info = {
        "name": os.path.basename(file_path),
        "size": get_file_size(file_path),
        "extension": get_file_extension(file_path),
        "sha256": calculate_sha256(file_path),
    }

    # --------------------------------------------------------
    # PE information
    # --------------------------------------------------------

    pe_is_valid = is_pe_file(
        file_path
    )

    pe_info = {
        "is_pe": pe_is_valid,
        "architecture": (
            get_pe_architecture(file_path)
            if pe_is_valid
            else "Not a PE file"
        ),
        "entry_point": (
            get_pe_entry_point(file_path)
            if pe_is_valid
            else None
        ),
        "timestamp": (
            format_pe_timestamp(
                get_pe_timestamp(file_path)
            )
            if pe_is_valid
            else None
        ),
        "sections": (
            get_pe_sections(file_path)
            if pe_is_valid
            else None
        ),
        "section_details": (
            get_pe_section_details(file_path)
            if pe_is_valid
            else None
        ),
        "subsystem": (
            get_pe_subsystem(file_path)
            if pe_is_valid
            else None
        ),
    }

    # --------------------------------------------------------
    # Imports
    # --------------------------------------------------------

    imports = []

    import_directory = None

    if pe_is_valid:
        imports = get_pe_imports(
            file_path
        )

        import_directory = (
            get_pe_import_directory(
                file_path
            )
        )

    # --------------------------------------------------------
    # Static API analysis
    # --------------------------------------------------------

    indicators = analyze_imports(
        imports
    )

    imported_functions = get_imported_api_names(
        imports
    )

    # --------------------------------------------------------
    # String analysis
    # --------------------------------------------------------

    strings = extract_strings(
        file_path
    )

    powershell_findings = analyze_powershell(
        strings
    )

    powershell_summary = get_powershell_summary(
        powershell_findings
    )

    # --------------------------------------------------------
    # Behavioral combinations
    # --------------------------------------------------------

    combinations = analyze_behavior_combinations(
        imported_functions,
        powershell_summary
    )

    # --------------------------------------------------------
    # Triage scoring
    # --------------------------------------------------------

    indicator_score = calculate_indicator_score(
        indicators,
        combinations,
        powershell_summary
    )

    triage_level = get_triage_level(
        indicator_score,
        combinations,
        powershell_summary
    )

    # --------------------------------------------------------
    # Indicator counts
    # --------------------------------------------------------

    high_indicators = sum(
        1
        for indicator in indicators
        if indicator["confidence"] == "HIGH"
    )

    medium_indicators = sum(
        1
        for indicator in indicators
        if indicator["confidence"] == "MEDIUM"
    )

    low_indicators = sum(
        1
        for indicator in indicators
        if indicator["confidence"] == "LOW"
    )

    # --------------------------------------------------------
    # Import directory information
    # --------------------------------------------------------

    import_directory_info = None

    if import_directory:
        import_rva = int(
            import_directory["rva"],
            16
        )

        descriptors = get_pe_import_descriptors(
            file_path
        )

        import_directory_info = {
            "rva": import_directory["rva"],
            "size": import_directory["size"],
            "file_offset": rva_to_file_offset(
                file_path,
                import_rva
            ),
            "descriptor_count": len(
                descriptors or []
            ),
        }

    # --------------------------------------------------------
    # Final structured result
    # --------------------------------------------------------

    return {
        "file": file_info,

        "pe": pe_info,

        "imports": imports,

        "import_directory": import_directory_info,

        "strings": strings,

        "static_analysis": {
            "indicators": indicators,
            "counts": {
                "high": high_indicators,
                "medium": medium_indicators,
                "low": low_indicators,
            },
        },

        "powershell": powershell_summary,

        "behavioral_combinations": combinations,

        "triage": {
            "score": indicator_score,
            "level": triage_level,
        },
    }

# ============================================================
# FILE ANALYSIS ENGINE
# ============================================================

def analyze_file(file_path):
    """
    Run the complete static analysis pipeline on a file.

    Returns a structured dictionary suitable for consumption
    by IOCYRA or other interfaces.
    """

    # --------------------------------------------------------
    # Basic file information
    # --------------------------------------------------------

    sha256 = calculate_sha256(file_path)
    file_size = get_file_size(file_path)
    extension = get_file_extension(file_path)

    # --------------------------------------------------------
    # PE analysis
    # --------------------------------------------------------

    pe_file = is_pe_file(file_path)

    pe_info = {
        "is_pe": pe_file,
        "architecture": None,
        "entry_point": None,
        "timestamp": None,
        "sections": None,
        "section_details": None,
        "subsystem": None,
    }

    if pe_file:
        timestamp = get_pe_timestamp(file_path)

        pe_info.update({
            "architecture":
                get_pe_architecture(file_path),

            "entry_point":
                get_pe_entry_point(file_path),

            "timestamp":
                format_pe_timestamp(timestamp),

            "sections":
                get_pe_sections(file_path),

            "section_details":
                get_pe_section_details(file_path),

            "subsystem":
                get_pe_subsystem(file_path),
        })

    # --------------------------------------------------------
    # Imports
    # --------------------------------------------------------

    imports = []

    import_directory = None
    import_directory_offset = None
    import_descriptors = 0

    if pe_file:
        imports = get_pe_imports(file_path)

        import_directory = get_pe_import_directory(
            file_path
        )

        if import_directory:
            import_rva = int(
                import_directory["rva"],
                16
            )

            import_directory_offset = (
                rva_to_file_offset(
                    file_path,
                    import_rva
                )
            )

            descriptors = get_pe_import_descriptors(
                file_path
            )

            import_descriptors = (
                len(descriptors)
                if descriptors
                else 0
            )

    # --------------------------------------------------------
    # Static API analysis
    # --------------------------------------------------------

    indicators = analyze_imports(
        imports
    )

    imported_functions = get_imported_api_names(
        imports
    )

    # --------------------------------------------------------
    # String analysis
    # --------------------------------------------------------

    strings = extract_strings(
        file_path
    )

    powershell_findings = analyze_powershell(
        strings
    )

    powershell_summary = get_powershell_summary(
        powershell_findings
    )

    # --------------------------------------------------------
    # Behavioral combinations
    # --------------------------------------------------------

    combinations = analyze_behavior_combinations(
        imported_functions,
        powershell_summary
    )

    # --------------------------------------------------------
    # Triage
    # --------------------------------------------------------

    indicator_score = calculate_indicator_score(
        indicators,
        combinations,
        powershell_summary
    )

    triage_level = get_triage_level(
        indicator_score,
        combinations
    )

    # --------------------------------------------------------
    # Indicator counts
    # --------------------------------------------------------

    high_indicators = sum(
        1
        for indicator in indicators
        if indicator["confidence"] == "HIGH"
    )

    medium_indicators = sum(
        1
        for indicator in indicators
        if indicator["confidence"] == "MEDIUM"
    )

    low_indicators = sum(
        1
        for indicator in indicators
        if indicator["confidence"] == "LOW"
    )

    # --------------------------------------------------------
    # Return structured analysis result
    # --------------------------------------------------------

    return {
        "file": {
            "name": os.path.basename(file_path),
            "path": file_path,
            "size": file_size,
            "extension": extension,
            "sha256": sha256,
        },

        "pe": pe_info,

        "imports": {
            "dlls": imports,
            "directory": import_directory,
            "directory_offset": import_directory_offset,
            "descriptor_count": import_descriptors,
        },

        "strings": {
            "count": len(strings),
            "values": strings,
        },

        "static_analysis": {
            "indicators": indicators,

            "counts": {
                "high": high_indicators,
                "medium": medium_indicators,
                "low": low_indicators,
            },
        },

        "powershell": powershell_summary,

        "behavioral_combinations": combinations,

        "triage": {
            "score": indicator_score,
            "level": triage_level,
        },
    }

# ============================================================
# TEST / DEBUG
# ============================================================

def print_analysis_report(result):
    """
    Print a human-readable representation of an analysis result.

    This is intended for development/debugging only.
    IOCYRA itself should consume the structured result directly.
    """

    file_info = result["file"]
    pe_info = result["pe"]
    imports_info = result["imports"]
    static_analysis = result["static_analysis"]
    powershell = result["powershell"]
    combinations = result["behavioral_combinations"]
    triage = result["triage"]

    print(
        "SHA-256:",
        file_info["sha256"]
    )

    print(
        "File size:",
        file_info["size"],
        "bytes"
    )

    print(
        "Extension:",
        file_info["extension"]
    )

    print(
        "PE file:",
        pe_info["is_pe"]
    )

    print(
        "Architecture:",
        pe_info["architecture"]
    )

    print(
        "Entry point:",
        pe_info["entry_point"]
    )

    print(
        "PE timestamp:",
        pe_info["timestamp"]
    )

    print(
        "PE sections:",
        pe_info["sections"]
    )

    print(
        "PE section details:",
        pe_info["section_details"]
    )

    print(
        "Subsystem:",
        pe_info["subsystem"]
    )

    # --------------------------------------------------------
    # Imports
    # --------------------------------------------------------

    print(
        "Imported DLLs and functions:"
    )

    for import_entry in imports_info["dlls"]:
        print(
            f"  {import_entry['dll']}"
        )

        for function in import_entry["functions"]:
            if function["import_type"] == "name":
                print(
                    f"    - {function['name']}"
                )

            else:
                print(
                    f"    - Ordinal #{function['ordinal']}"
                )

    # --------------------------------------------------------
    # Import directory
    # --------------------------------------------------------

    import_directory = imports_info["directory"]

    if import_directory:
        print(
            "Import directory RVA:",
            import_directory["rva"]
        )

        print(
            "Import directory size:",
            import_directory["size"]
        )

        print(
            "Import directory file offset:",
            imports_info["directory_offset"]
        )

        print(
            "Import descriptors:",
            imports_info["descriptor_count"]
        )

    # --------------------------------------------------------
    # Static API results
    # --------------------------------------------------------

    print()
    print(
        "=== Static Analysis ==="
    )

    indicators = static_analysis["indicators"]

    if not indicators:
        print(
            "No categorized behavioral indicators detected."
        )

    else:
        for indicator in indicators:
            print()

            print(
                f"[+] {indicator['category']}"
            )

            print(
                f"    Confidence: "
                f"{indicator['confidence']}"
            )

            print(
                f"    {indicator['description']}"
            )

            for api in indicator["apis"]:
                print(
                    f"    - {api}"
                )

    # --------------------------------------------------------
    # PowerShell
    # --------------------------------------------------------

    print()
    print(
        "=== PowerShell Analysis ==="
    )

    if not powershell:
        print(
            "No PowerShell-related string indicators detected."
        )

    else:
        print(
            f"Overall confidence: "
            f"{powershell['confidence']}"
        )

        for finding in powershell["findings"]:
            print()

            print(
                f"[!] {finding['category']}"
            )

            print(
                f"    Confidence: "
                f"{finding['confidence']}"
            )

            print(
                f"    {finding['description']}"
            )

            print(
                "    Matching strings:"
            )

            for value in finding["matches"][:10]:
                print(
                    f"      - {value}"
                )

            if len(finding["matches"]) > 10:
                print(
                    f"      ... and "
                    f"{len(finding['matches']) - 10} more"
                )

    # --------------------------------------------------------
    # Behavioral combinations
    # --------------------------------------------------------

    print()
    print(
        "=== Behavioral Combinations ==="
    )

    if not combinations:
        print(
            "No significant behavioral combinations detected."
        )

    else:
        for combination in combinations:
            print()

            print(
                f"[+] {combination['category']}"
            )

            print(
                f"    Confidence: "
                f"{combination['confidence']}"
            )

            print(
                f"    {combination['description']}"
            )

            if combination["apis"]:
                print(
                    "    Supporting APIs:"
                )

                for api in combination["apis"]:
                    print(
                        f"      - {api}"
                    )

    # --------------------------------------------------------
    # Triage summary
    # --------------------------------------------------------

    counts = static_analysis["counts"]

    print()
    print(
        "=== Triage Summary ==="
    )

    print(
        "Indicator score:",
        triage["score"]
    )

    print(
        "High-confidence indicators:",
        counts["high"]
    )

    print(
        "Medium-confidence indicators:",
        counts["medium"]
    )

    print(
        "Low-confidence indicators:",
        counts["low"]
    )

    print(
        "Behavioral combinations:",
        len(combinations)
    )

    print(
        "Triage level:",
        triage["level"]
    )

    print()

    print(
        "Note: Static analysis identifies file capabilities, "
        "embedded strings, and suspicious combinations. "
        "A finding does not prove that the file executed "
        "the associated behavior or that it is malicious."
    )


if __name__ == "__main__":
    file_path = "yarascanner.exe"

    result = analyze_file(
        file_path
    )

    print_analysis_report(
        result
    )