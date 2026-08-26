"""DMI / boot-mode identity. All reads are best-effort and non-fatal."""

import ctypes
import os
import shutil
import subprocess

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

# Detection only -- we report versions, we never install or fetch these.
OPTIONAL_TOOLS = ("UEFIExtract", "uefiextract", "ifrextractor", "chipsec_util", "fwupdmgr")


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


def firmware_capability() -> dict[str, str]:
    """Report whether Windows firmware variables can be read by this process."""
    try:
        return _capability(_windows_firmware_type(), _windows_variable_error())
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


def optional_tools() -> dict[str, str | None]:
    found: dict[str, str | None] = {}
    for tool in OPTIONAL_TOOLS:
        path = shutil.which(tool)
        if path is None:
            continue
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no user input
                [path, "--version"], capture_output=True, text=True, timeout=10, check=False
            )
            stdout = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            stderr = [line.strip() for line in proc.stderr.splitlines() if line.strip()]
            if proc.returncode:
                detail = (stderr or stdout or [f"exit {proc.returncode}"])[0]
                found[tool] = f"{path} (version check failed: {detail})"
            else:
                found[tool] = (stdout or stderr or [path])[0]
        except (OSError, subprocess.SubprocessError) as exc:
            found[tool] = f"{path} (version check failed: {exc})"
    return found


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
