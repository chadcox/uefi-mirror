"""DMI / boot-mode identity. All reads are best-effort and non-fatal."""

import ctypes
import json
import os
import shutil

from . import safety

WINDOWS = os.name == "nt"
DMI_DIR = "/sys/class/dmi/id" if not WINDOWS else None
DMI_FIELDS = (
    "sys_vendor", "product_name", "board_vendor", "board_name", "board_version",
    "bios_vendor", "bios_version", "bios_date", "bios_release",
)
EFI_DIR = "/sys/firmware/efi" if not WINDOWS else None
EFIVARS_DIR = "/sys/firmware/efi/efivars" if not WINDOWS else None
FW_ATTRS_DIR = "/sys/class/firmware-attributes" if not WINDOWS else None

RSMB = int.from_bytes(b"RSMB", "big")
MAX_SMBIOS_BYTES = 16 * 1024 * 1024
ERROR_ACCESS_DENIED = 5
ERROR_PRIVILEGE_NOT_HELD = 1314

# Detection only -- we never install, fetch or run these. fwupdmgr alone is
# queried, through safety.run_readonly_tool; the rest are reported by path.
OPTIONAL_TOOLS = ("UEFIExtract", "uefiextract", "ifrextractor", "chipsec_util", "fwupdmgr")
TOOL_VERSION_TIMEOUT_SECONDS = 10
# fwupd assembles these from its plugins, the kernel, sysfs and UEFI data; they
# are recorded as fwupd reported them, never as reads made by uefi-mirror.
FWUPD_COMMANDS = (
    ("version", ("fwupdmgr", "--version")),
    ("security", ("fwupdmgr", "security", "--json")),
    ("devices", ("fwupdmgr", "get-devices", "--json")),
)
FWUPD_TIMEOUT_SECONDS = 30


def dmi() -> dict[str, str]:
    if WINDOWS:
        try:
            return _parse_smbios(_windows_smbios())
        except OSError:
            return {}
    out = {}
    for f in DMI_FIELDS:
        try:
            with open(os.path.join(DMI_DIR, f), encoding="utf-8", errors="replace") as fh:
                out[f] = fh.read().strip()
        except OSError:
            pass
    return out


def _kernel32():
    return getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)


def _windows_smbios() -> bytes:
    get_table = _kernel32().GetSystemFirmwareTable
    get_table.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32]
    get_table.restype = ctypes.c_uint32
    size = get_table(RSMB, 0, None, 0)
    if not size:
        raise ctypes.WinError(ctypes.get_last_error())
    if size > MAX_SMBIOS_BYTES:
        raise OSError(f"SMBIOS table is implausibly large: {size} bytes")
    buffer = ctypes.create_string_buffer(size)
    written = get_table(RSMB, 0, buffer, size)
    if not written:
        raise ctypes.WinError(ctypes.get_last_error())
    if written > size:
        raise OSError(f"SMBIOS table grew while reading: {size} to {written} bytes")
    return buffer.raw[:written]


def _parse_smbios(raw: bytes) -> dict[str, str]:
    if len(raw) < 8:
        return {}
    length = int.from_bytes(raw[4:8], "little")
    if length > len(raw) - 8:
        return {}
    table = raw[8:8 + length]
    out: dict[str, str] = {}
    pos = 0
    while pos + 4 <= len(table):
        kind, formatted_length = table[pos], table[pos + 1]
        if formatted_length < 4 or pos + formatted_length > len(table):
            break
        strings_start = pos + formatted_length
        strings_end = table.find(b"\0\0", strings_start)
        if strings_end < 0:
            break
        strings = table[strings_start:strings_end].split(b"\0") if strings_end > strings_start else []

        def string(offset: int) -> str:
            index = table[pos + offset] if offset < formatted_length else 0
            if not index or index > len(strings):
                return ""
            return strings[index - 1].decode("utf-8", errors="replace").strip()

        fields = {}
        if kind == 0:
            fields = {"bios_vendor": string(4), "bios_version": string(5),
                      "bios_date": string(8)}
            if formatted_length > 21 and table[pos + 20:pos + 22] != b"\xff\xff":
                fields["bios_release"] = f"{table[pos + 20]}.{table[pos + 21]}"
        elif kind == 1:
            fields = {"sys_vendor": string(4), "product_name": string(5)}
        elif kind == 2:
            fields = {"board_vendor": string(4), "board_name": string(5),
                      "board_version": string(6)}
        for key, value in fields.items():
            if value:
                out.setdefault(key, value)
        pos = strings_end + 2
        if kind == 127:
            break
    return out


def _windows_firmware_type() -> int:
    firmware_type = ctypes.c_uint32()
    get_type = _kernel32().GetFirmwareType
    get_type.argtypes = [ctypes.POINTER(ctypes.c_uint32)]
    get_type.restype = ctypes.c_int32
    if not get_type(ctypes.byref(firmware_type)):
        raise ctypes.WinError(ctypes.get_last_error())
    return firmware_type.value


def _windows_variable_error() -> int:
    get_variable = _kernel32().GetFirmwareEnvironmentVariableW
    get_variable.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p,
                             ctypes.c_void_p, ctypes.c_uint32]
    get_variable.restype = ctypes.c_uint32
    ctypes.set_last_error(0)
    get_variable("", "{00000000-0000-0000-0000-000000000000}", None, 0)
    return ctypes.get_last_error()


def _capability(firmware_type: int, variable_error: int) -> dict[str, str]:
    if firmware_type == 1:
        return {"status": "not_uefi", "message": "Windows was booted in legacy BIOS mode"}
    if firmware_type != 2:
        return {"status": "unavailable", "message": "Windows could not determine firmware type"}
    if variable_error in (ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD):
        return {"status": "needs_elevation",
                "message": "run from an elevated Administrator terminal"}
    return {"status": "ready", "message": "UEFI firmware variables are available"}


def _enable_environment_privilege() -> None:
    """Best-effort enable of SeSystemEnvironmentPrivilege for the probe.

    Never raises: if the privilege is genuinely unavailable the firmware getter
    fails and _capability reports needs_elevation. Enabling a privilege the token
    already holds does not elevate — it only flips it from present to enabled,
    which is exactly what an already-Administrator process needs to be classified
    ready instead of being told to elevate again.
    """
    try:
        # Lazy import: collectors.windows -> efivarfs -> platform would be a cycle.
        from .collectors.windows import enable_privilege
        enable_privilege()
    except (OSError, PermissionError):
        pass


def firmware_capability() -> dict[str, str]:
    """Report whether Windows firmware variables can be read by this process."""
    try:
        firmware_type = _windows_firmware_type()
        if firmware_type == 2:
            _enable_environment_privilege()
        return _capability(firmware_type, _windows_variable_error())
    except OSError as exc:
        return {"status": "unavailable", "message": str(exc)}


def efivarfs_mounted() -> bool:
    """True only if efivars is really an efivarfs mount, not a stale directory."""
    if WINDOWS:
        return False
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split(" - ")
                if len(parts) != 2:
                    continue
                if parts[0].split()[4] == EFIVARS_DIR and parts[1].split()[0] == "efivarfs":
                    return True
    except OSError:
        pass
    return False


def firmware_attributes() -> dict[str, dict[str, str]]:
    """Vendor BIOS settings exposed by the kernel, if any driver provides them."""
    if WINDOWS:
        return {}
    result: dict[str, dict[str, str]] = {}
    try:
        devices = sorted(os.listdir(FW_ATTRS_DIR))
    except OSError:
        return result
    for dev in devices:
        attrs_dir = os.path.join(FW_ATTRS_DIR, dev, "attributes")
        settings: dict[str, str] = {}
        try:
            names = sorted(os.listdir(attrs_dir))
        except OSError:
            continue
        for name in names:
            try:
                with open(os.path.join(attrs_dir, name, "current_value"), encoding="utf-8") as fh:
                    settings[name] = fh.read().strip()
            except OSError:
                continue
        result[dev] = settings
    return result


def _lines(data: bytes) -> list[str]:
    return [line.strip() for line in data.decode("utf-8", "replace").splitlines()
            if line.strip()]


def _fwupd_version(lines: list[str]) -> str | None:
    """Return the running fwupd's own version from `fwupdmgr --version`.

    fwupd 2.x prints "<compile|runtime> <component> <version>" records,
    dependencies first; 1.x prints "daemon version:" and "client version:"
    lines. Prefer the running daemon's version; anything else is unrecognised.
    """
    records = [line.split() for line in lines]
    fwupd_records = [r for r in records if len(r) == 3 and r[1] == "org.freedesktop.fwupd"]
    if fwupd_records:
        runtime = [r for r in fwupd_records if r[0] == "runtime"]
        return (runtime or fwupd_records)[0][2]
    legacy = {r[0]: r[2] for r in records
              if len(r) == 3 and r[0] in ("daemon", "client") and r[1] == "version:"}
    return legacy.get("daemon") or legacy.get("client")


def optional_tools() -> dict[str, str]:
    found: dict[str, str] = {}
    for tool in OPTIONAL_TOOLS:
        if tool != "fwupdmgr":
            path = shutil.which(tool)
            if path is not None:
                found[tool] = path
            continue
        try:
            result = safety.run_readonly_tool((tool, "--version"),
                                              timeout=TOOL_VERSION_TIMEOUT_SECONDS)
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            found[tool] = f"version check failed: {exc}"
            continue
        stdout, stderr = _lines(result.stdout), _lines(result.stderr)
        if result.returncode:
            detail = (stderr or stdout or [f"exit {result.returncode}"])[0]
            found[tool] = f"{result.path} (version check failed: {detail})"
            continue
        lines = stdout or stderr or [result.path]
        found[tool] = _fwupd_version(lines) or lines[0]
    return found


def _fwupd_record(command: tuple[str, ...], result: safety.ToolResult) -> dict:
    record = {"command": list(command), "program": result.path}
    if result.returncode:
        detail = (_lines(result.stderr) or _lines(result.stdout) or [""])[0]
        return {**record, "available": False,
                "error": f"exit status {result.returncode}" + (f": {detail}" if detail else "")}
    if command[1] == "--version":
        lines = _lines(result.stdout)
        version = _fwupd_version(lines)
        if version is None:
            first = lines[0] if lines else "no output"
            return {**record, "available": False,
                    "error": f"unrecognised version output: {first}"}
        return {**record, "available": True, "output": version}
    try:
        output = json.loads(result.stdout)
    except (ValueError, RecursionError) as exc:
        return {**record, "available": False, "error": f"invalid JSON: {exc}"}
    if not isinstance(output, dict):
        return {**record, "available": False, "error": "unexpected JSON: expected an object"}
    return {**record, "available": True, "output": output}


def fwupd() -> dict:
    """What fwupd reports about host security and device firmware, attributed to it.

    Each command's JSON is kept exactly as fwupd emitted it, with the command
    and program that produced it. A failing command is recorded with its error
    and the others still run; nothing is inferred from a missing answer.
    """
    report: dict = {"reported_by": "fwupd"}
    if WINDOWS:
        return {**report, "available": False, "error": "fwupd is not available on Windows"}
    records: dict[str, dict] = {}
    for key, command in FWUPD_COMMANDS:
        try:
            result = safety.run_readonly_tool(command, timeout=FWUPD_TIMEOUT_SECONDS)
        except FileNotFoundError as exc:
            return {**report, "available": False, "error": str(exc)}
        except (OSError, ValueError) as exc:
            records[key] = {"command": list(command), "available": False, "error": str(exc)}
            continue
        records[key] = _fwupd_record(command, result)
    return {**report, "available": True, **records}


def summary() -> dict:
    if WINDOWS:
        capability = firmware_capability()
        return {
            "uefi_boot": {"not_uefi": False, "needs_elevation": True,
                          "ready": True}.get(capability["status"]),
            "efivarfs_mounted": False,
            "euid": None,
            "dmi": dmi(),
            "firmware_attributes": {},
            "optional_tools": optional_tools(),
            "firmware_variables": capability,
        }
    return {
        "uefi_boot": os.path.isdir(EFI_DIR),
        "efivarfs_mounted": efivarfs_mounted(),
        "euid": os.geteuid(),
        "dmi": dmi(),
        "firmware_attributes": firmware_attributes(),
        "optional_tools": optional_tools(),
    }
