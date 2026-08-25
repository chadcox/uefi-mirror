"""DMI / boot-mode identity. All reads are best-effort and non-fatal."""

import os
import shutil
import subprocess

DMI_DIR = "/sys/class/dmi/id"
DMI_FIELDS = (
    "sys_vendor", "product_name", "board_vendor", "board_name", "board_version",
    "bios_vendor", "bios_version", "bios_date", "bios_release",
)
EFI_DIR = "/sys/firmware/efi"
EFIVARS_DIR = "/sys/firmware/efi/efivars"
FW_ATTRS_DIR = "/sys/class/firmware-attributes"

# Detection only -- we report versions, we never install or fetch these.
OPTIONAL_TOOLS = ("UEFIExtract", "uefiextract", "ifrextractor", "chipsec_util", "fwupdmgr")


def dmi() -> dict[str, str]:
    out = {}
    for f in DMI_FIELDS:
        try:
            with open(os.path.join(DMI_DIR, f), encoding="utf-8", errors="replace") as fh:
                out[f] = fh.read().strip()
        except OSError:
            pass
    return out


def efivarfs_mounted() -> bool:
    """True only if efivars is really an efivarfs mount, not a stale directory."""
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
    return {
        "uefi_boot": os.path.isdir(EFI_DIR),
        "efivarfs_mounted": efivarfs_mounted(),
        "euid": os.geteuid(),
        "dmi": dmi(),
        "firmware_attributes": firmware_attributes(),
        "optional_tools": optional_tools(),
    }
