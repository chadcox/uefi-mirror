"""Read-only primitives. Nothing here may ever open a file for writing
inside /sys/firmware. Enforced by tests/test_safety.py."""

import ctypes
import errno
import http.client
import ipaddress
import os
import re
import socket
import ssl
import stat
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from . import __version__

# efivarfs vars are kernel-capped well under this; the limit is belt-and-braces
# against a hostile/buggy filesystem handing us an endless read.
MAX_VARIABLE_BYTES = 1 << 20
MAX_METADATA_BYTES = 4 << 20
MAX_ARTIFACT_BYTES = 128 << 20
MAX_REDIRECTS = 5
MAX_HTTP_REQUESTS = 20
HTTP_TIMEOUT_SECONDS = 15
FETCH_DEADLINE_SECONDS = 180
HTTP_READ_CHUNK = 64 << 10
WINDOWS = os.name == "nt"

# A firmware variable name is attacker-influenced on Windows (it comes back from
# the firmware, not the OS), and snapshot writes it as a filename. Validate it as
# a single, contained path component on BOTH platforms before it can name a file.
_UNSAFE_COMPONENT = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL",
                   *(f"COM{i}" for i in range(1, 10)),
                   *(f"LPT{i}" for i in range(1, 10))}


@dataclass
class HttpBudget:
    deadline: float = field(
        default_factory=lambda: time.monotonic() + FETCH_DEADLINE_SECONDS)
    requests: int = 0

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("whole fetch deadline exceeded")
        return remaining

    def claim_request(self) -> float:
        if self.requests >= MAX_HTTP_REQUESTS:
            raise ValueError(f"fetch exceeds the {MAX_HTTP_REQUESTS} request limit")
        timeout = min(HTTP_TIMEOUT_SECONDS, self.remaining())
        self.requests += 1
        return timeout


@dataclass(frozen=True)
class HttpResult:
    data: bytes
    final_url: str


def _validate_https_url(url: str, allowed_hosts: frozenset[str]) -> None:
    if (not isinstance(url, str) or not url
            or any(ord(char) <= 32 or ord(char) >= 127 for char in url)):
        raise ValueError("HTTPS URL is empty or contains unsafe characters")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("HTTPS URL has a malformed authority") from exc
    if parsed.scheme.casefold() != "https":
        raise ValueError("only HTTPS URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials are refused")
    host = parsed.hostname
    if not host or parsed.fragment:
        raise ValueError("HTTPS URL has a malformed authority or fragment")
    host = host.casefold()
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("localhost URLs are refused")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("IP-literal URLs are refused")
    if port not in (None, 443):
        raise ValueError("only HTTPS port 443 is allowed")
    if host not in {allowed.casefold() for allowed in allowed_hosts}:
        raise ValueError(f"HTTPS host {host!r} is not approved")


class _CheckedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: frozenset[str], budget: HttpBudget, stage: str):
        self.allowed_hosts = allowed_hosts
        self.budget = budget
        self.stage = stage

    def http_error_302(self, req, fp, code, msg, headers):
        location = headers.get("Location") or headers.get("URI")
        if location is None:
            fp.close()
            raise ValueError(f"{self.stage}: redirect has no Location")
        try:
            if not isinstance(location, str):
                raise ValueError("redirect Location must be text")
            target = urljoin(req.full_url, location)
            _validate_https_url(target, self.allowed_hosts)
            redirects = getattr(req, "_uefi_redirects", 0) + 1
            if redirects > MAX_REDIRECTS:
                raise ValueError(f"exceeds the {MAX_REDIRECTS} redirect limit")
            redirected = self.redirect_request(req, fp, code, msg, headers, target)
            if redirected is None:
                raise ValueError(f"{self.stage}: unsupported HTTP redirect")
            redirected._uefi_redirects = redirects
        except (TypeError, ValueError) as exc:
            fp.close()
            raise ValueError(f"{self.stage}: redirect refused: {exc}") from exc
        except Exception:
            fp.close()
            raise
        fp.close()
        return self.parent.open(
            redirected, timeout=min(HTTP_TIMEOUT_SECONDS, self.budget.remaining()))

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def _response_timeout(response, timeout: float) -> None:
    raw = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
    if raw is not None:
        raw.settimeout(timeout)


def _network_failure(stage: str, exc: BaseException) -> ValueError:
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, (TimeoutError, socket.timeout)):
        detail = "timed out"
    elif isinstance(reason, ssl.SSLCertVerificationError):
        detail = "TLS certificate verification failed"
    else:
        message = "".join(char if char.isprintable() else "?" for char in str(reason))[:200]
        detail = f"network request failed: {message}"
    return ValueError(f"{stage}: {detail}")


def read_https(
    url: str, limit: int, allowed_hosts: frozenset[str], *, stage: str,
    budget: HttpBudget,
) -> HttpResult:
    """Read one approved HTTPS resource with shared request/deadline limits."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("HTTPS byte limit must be a positive integer")
    try:
        _validate_https_url(url, allowed_hosts)
    except ValueError as exc:
        raise ValueError(f"{stage}: {exc}") from exc
    timeout = budget.claim_request()
    redirect = _CheckedRedirectHandler(allowed_hosts, budget, stage)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), redirect)
    request = urllib.request.Request(
        url, headers={"Accept-Encoding": "identity",
                      "User-Agent": f"uefi-mirror/{__version__}"})
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        exc.close()
        raise ValueError(f"{stage}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise _network_failure(stage, exc) from exc

    try:
        with response:
            try:
                _validate_https_url(response.geturl(), allowed_hosts)
            except ValueError as exc:
                raise ValueError(f"{stage}: final URL refused: {exc}") from exc
            encoding = response.headers.get("Content-Encoding", "identity")
            if not isinstance(encoding, str):
                raise ValueError(f"{stage}: invalid Content-Encoding")
            encoding = encoding.strip().casefold()
            if encoding not in ("", "identity"):
                raise ValueError(f"{stage}: unsupported Content-Encoding {encoding!r}")
            raw_length = response.headers.get("Content-Length")
            declared = None
            if raw_length is not None:
                if not isinstance(raw_length, str):
                    raise ValueError(f"{stage}: invalid Content-Length")
                raw_length = raw_length.strip()
                if not re.fullmatch(r"[0-9]+", raw_length):
                    raise ValueError(f"{stage}: invalid Content-Length")
                declared = int(raw_length)
                if declared > limit:
                    raise ValueError(f"{stage}: exceeds the {limit} byte limit")

            data = bytearray()
            while len(data) <= limit:
                remaining = budget.remaining()
                _response_timeout(response, min(HTTP_TIMEOUT_SECONDS, remaining))
                chunk = response.read(min(HTTP_READ_CHUNK, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > limit:
                raise ValueError(f"{stage}: exceeds the {limit} byte limit")
            if declared is not None and len(data) != declared:
                raise ValueError(
                    f"{stage}: response ended at {len(data)} bytes, expected {declared}")
            return HttpResult(bytes(data), response.geturl())
    except (http.client.HTTPException, OSError) as exc:
        raise _network_failure(stage, exc) from exc


def safe_component(name: str) -> bool:
    """True if `name` is safe as one on-disk filename component on POSIX and
    Windows: no separators or traversal, no NUL/control chars, no Windows
    reserved name, no trailing dot or space (Windows strips those silently)."""
    if not name or len(name) > 255 or name in (".", ".."):
        return False
    if _UNSAFE_COMPONENT.search(name):
        return False
    if name[-1] in ". ":
        return False
    return name.split(".", 1)[0].upper() not in _RESERVED_NAMES

RO_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)

SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x00000001
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
SE_DACL_PROTECTED = 0x1000
ACL_REVISION = 2
ACCESS_ALLOWED_ACE_TYPE = 0
FILE_ALL_ACCESS = 0x001F01FF
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
OPEN_ALWAYS = 4
OPEN_EXISTING = 3
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
TOKEN_QUERY = 0x0008
TOKEN_USER = 1
SECURITY_DESCRIPTOR_REVISION = 1
SECURITY_DESCRIPTOR_MIN_LENGTH = 64
ERROR_ALREADY_EXISTS = 183


class _ACL(ctypes.Structure):
    _fields_ = [("AclRevision", ctypes.c_ubyte), ("Sbz1", ctypes.c_ubyte),
                ("AclSize", ctypes.c_ushort), ("AceCount", ctypes.c_ushort),
                ("Sbz2", ctypes.c_ushort)]


class _ACE_HEADER(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte),
                ("AceSize", ctypes.c_ushort)]


class _ACCESS_ALLOWED_ACE(ctypes.Structure):
    _fields_ = [("Header", _ACE_HEADER), ("Mask", ctypes.c_uint32),
                ("SidStart", ctypes.c_uint32)]


class _FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
    _fields_ = [("FileAttributes", ctypes.c_uint32), ("ReparseTag", ctypes.c_uint32)]


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", ctypes.c_uint32),
                ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", ctypes.c_int32)]


class _TOKEN_USER(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", ctypes.c_uint32)]


def _dll(name: str):
    return getattr(ctypes, "WinDLL")(name, use_last_error=True)


def _close_windows_handle(handle: int) -> None:
    close = _dll("kernel32").CloseHandle
    close.argtypes, close.restype = [ctypes.c_void_p], ctypes.c_int32
    close(handle)


def _open_windows_handle(path: str, access: int, disposition: int,
                         directory: bool = False, sec_attr=None) -> int:
    """Open the named object itself and refuse any final-component reparse point.

    When `sec_attr` is given and the disposition creates the object, it is created
    with that private security descriptor already in place — no inherited-DACL
    window. On an existing object the descriptor is ignored by CreateFileW.
    """
    kernel32 = _dll("kernel32")
    create = kernel32.CreateFileW
    create.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                       ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    create.restype = ctypes.c_void_p
    flags = FILE_FLAG_OPEN_REPARSE_POINT | (
        FILE_FLAG_BACKUP_SEMANTICS if directory else FILE_ATTRIBUTE_NORMAL)
    handle = create(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ctypes.byref(sec_attr) if sec_attr is not None else None,
                    disposition, flags, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())

    get_info = kernel32.GetFileInformationByHandleEx
    get_info.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    get_info.restype = ctypes.c_int32
    info = _FILE_ATTRIBUTE_TAG_INFO()
    if not get_info(handle, FILE_ATTRIBUTE_TAG_INFO_CLASS,
                    ctypes.byref(info), ctypes.sizeof(info)):
        error = ctypes.get_last_error()
        _close_windows_handle(handle)
        raise ctypes.WinError(error)
    if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
        _close_windows_handle(handle)
        raise OSError(errno.ELOOP, "reparse point refused", path)
    return handle


def _security_api():
    api = _dll("advapi32")
    api.GetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    api.GetNamedSecurityInfoW.restype = ctypes.c_uint32
    api.SetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    api.SetNamedSecurityInfoW.restype = ctypes.c_uint32
    api.GetLengthSid.argtypes, api.GetLengthSid.restype = [ctypes.c_void_p], ctypes.c_uint32
    api.InitializeAcl.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
    api.InitializeAcl.restype = ctypes.c_int32
    api.AddAccessAllowedAceEx.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_uint32, ctypes.c_void_p,
    ]
    api.AddAccessAllowedAceEx.restype = ctypes.c_int32
    api.GetAce.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                           ctypes.POINTER(ctypes.c_void_p)]
    api.GetAce.restype = ctypes.c_int32
    api.EqualSid.argtypes, api.EqualSid.restype = [ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int32
    api.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_uint32)]
    api.GetSecurityDescriptorControl.restype = ctypes.c_int32
    api.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                     ctypes.POINTER(ctypes.c_void_p)]
    api.OpenProcessToken.restype = ctypes.c_int32
    api.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                        ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    api.GetTokenInformation.restype = ctypes.c_int32
    api.CopySid.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
    api.CopySid.restype = ctypes.c_int32
    api.InitializeSecurityDescriptor.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    api.InitializeSecurityDescriptor.restype = ctypes.c_int32
    api.SetSecurityDescriptorOwner.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int32]
    api.SetSecurityDescriptorOwner.restype = ctypes.c_int32
    api.SetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.c_int32,
                                              ctypes.c_void_p, ctypes.c_int32]
    api.SetSecurityDescriptorDacl.restype = ctypes.c_int32
    api.SetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, ctypes.c_uint16,
                                                ctypes.c_uint16]
    api.SetSecurityDescriptorControl.restype = ctypes.c_int32
    return api


def _token_user_sid() -> "ctypes.Array":
    """Copy the current process token's user SID into a standalone buffer."""
    api = _security_api()
    kernel32 = _dll("kernel32")
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    token = ctypes.c_void_p()
    if not api.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = ctypes.c_uint32()
        api.GetTokenInformation(token, TOKEN_USER, None, 0, ctypes.byref(size))
        if not size.value:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(size.value)
        if not api.GetTokenInformation(token, TOKEN_USER, buffer, size.value,
                                       ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        user = ctypes.cast(buffer, ctypes.POINTER(_TOKEN_USER)).contents
        sid_len = api.GetLengthSid(user.Sid)
        sid = ctypes.create_string_buffer(sid_len)
        if not api.CopySid(sid_len, sid, user.Sid):
            raise ctypes.WinError(ctypes.get_last_error())
        return sid
    finally:
        _close_windows_handle(token)


def _private_security_attributes(sid: "ctypes.Array"):
    """Build a SECURITY_ATTRIBUTES with one owner-only, protected (non-inheriting)
    ACE, so the object is private the instant it is created — no window between
    creation with an inherited DACL and the later owner-only replacement.

    Returns the SECURITY_ATTRIBUTES and a keep-alive tuple the caller must hold
    until the create call returns, or the buffers are collected out from under it.
    """
    api = _security_api()
    sid_size = api.GetLengthSid(sid)
    if not sid_size:
        raise ctypes.WinError(ctypes.get_last_error())
    acl_size = (ctypes.sizeof(_ACL) + ctypes.sizeof(_ACCESS_ALLOWED_ACE)
                - ctypes.sizeof(ctypes.c_uint32) + sid_size + 3) & ~3
    acl = ctypes.create_string_buffer(acl_size)
    if not api.InitializeAcl(acl, acl_size, ACL_REVISION):
        raise ctypes.WinError(ctypes.get_last_error())
    if not api.AddAccessAllowedAceEx(acl, ACL_REVISION, 0, FILE_ALL_ACCESS, sid):
        raise ctypes.WinError(ctypes.get_last_error())
    descriptor = ctypes.create_string_buffer(SECURITY_DESCRIPTOR_MIN_LENGTH)
    if not api.InitializeSecurityDescriptor(descriptor, SECURITY_DESCRIPTOR_REVISION):
        raise ctypes.WinError(ctypes.get_last_error())
    if not api.SetSecurityDescriptorOwner(descriptor, sid, False):
        raise ctypes.WinError(ctypes.get_last_error())
    if not api.SetSecurityDescriptorDacl(descriptor, True, acl, False):
        raise ctypes.WinError(ctypes.get_last_error())
    if not api.SetSecurityDescriptorControl(descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED):
        raise ctypes.WinError(ctypes.get_last_error())
    attributes = _SECURITY_ATTRIBUTES()
    attributes.nLength = ctypes.sizeof(_SECURITY_ATTRIBUTES)
    attributes.lpSecurityDescriptor = ctypes.cast(descriptor, ctypes.c_void_p)
    attributes.bInheritHandle = False
    return attributes, (descriptor, acl, sid)


def _get_windows_security(path: str, information: int):
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    result = _security_api().GetNamedSecurityInfoW(
        path, SE_FILE_OBJECT, information, ctypes.byref(owner), None,
        ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if result:
        raise OSError(result, f"GetNamedSecurityInfoW failed: {path}")
    return owner, dacl, descriptor


def _free_windows_security(descriptor: ctypes.c_void_p) -> None:
    local_free = _dll("kernel32").LocalFree
    local_free.argtypes, local_free.restype = [ctypes.c_void_p], ctypes.c_void_p
    local_free(descriptor)


def _windows_acl_is_private(path: str) -> bool:
    """Return whether path has one owner-only ACE and a protected DACL."""
    api = _security_api()
    owner, dacl, descriptor = _get_windows_security(
        path, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
    try:
        if not owner.value or not dacl.value:
            return False
        acl = ctypes.cast(dacl, ctypes.POINTER(_ACL)).contents
        if acl.AceCount != 1:
            return False
        ace_pointer = ctypes.c_void_p()
        if not api.GetAce(dacl, 0, ctypes.byref(ace_pointer)):
            raise ctypes.WinError(ctypes.get_last_error())
        ace = ctypes.cast(ace_pointer, ctypes.POINTER(_ACCESS_ALLOWED_ACE)).contents
        ace_sid = ctypes.c_void_p(ace_pointer.value + _ACCESS_ALLOWED_ACE.SidStart.offset)
        control, revision = ctypes.c_uint16(), ctypes.c_uint32()
        if not api.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise ctypes.WinError(ctypes.get_last_error())
        return (ace.Header.AceType == ACCESS_ALLOWED_ACE_TYPE
                and ace.Header.AceFlags == 0
                and ace.Mask == FILE_ALL_ACCESS
                and bool(api.EqualSid(owner, ace_sid))
                and bool(control.value & SE_DACL_PROTECTED))
    finally:
        _free_windows_security(descriptor)


def _set_windows_private_acl(path: str) -> None:
    """Replace inheritance with one full-access ACE for the current owner."""
    api = _security_api()
    owner, _dacl, descriptor = _get_windows_security(path, OWNER_SECURITY_INFORMATION)
    try:
        sid_size = api.GetLengthSid(owner)
        if not sid_size:
            raise ctypes.WinError(ctypes.get_last_error())
        acl_size = (ctypes.sizeof(_ACL) + ctypes.sizeof(_ACCESS_ALLOWED_ACE)
                    - ctypes.sizeof(ctypes.c_uint32) + sid_size + 3) & ~3
        acl = ctypes.create_string_buffer(acl_size)
        if not api.InitializeAcl(acl, acl_size, ACL_REVISION):
            raise ctypes.WinError(ctypes.get_last_error())
        if not api.AddAccessAllowedAceEx(
                acl, ACL_REVISION, 0, FILE_ALL_ACCESS, owner):
            raise ctypes.WinError(ctypes.get_last_error())
        result = api.SetNamedSecurityInfoW(
            path, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, acl, None)
        if result:
            raise OSError(result, f"SetNamedSecurityInfoW failed: {path}")
    finally:
        _free_windows_security(descriptor)
    if not _windows_acl_is_private(path):
        raise PermissionError(f"owner-only Windows ACL could not be verified: {path}")


def _windows_fd(path: str, access: int, disposition: int, flags: int) -> int:
    import msvcrt

    # Create with the owner-only descriptor already applied (closes the H2 race);
    # keep-alive holds the SD buffers until CreateFileW has consumed them.
    sec_attr, _keep = _private_security_attributes(_token_user_sid())
    handle = _open_windows_handle(path, access, disposition, sec_attr=sec_attr)
    try:
        return msvcrt.open_osfhandle(handle, flags | os.O_BINARY)
    except Exception:
        _close_windows_handle(handle)
        raise


def read_bounded(path: str, limit: int = MAX_VARIABLE_BYTES) -> bytes:
    """Open O_RDONLY|O_NOFOLLOW|O_CLOEXEC and read at most `limit` bytes.

    Raises OSError(ELOOP) on a symlink, ValueError if the file exceeds `limit`.
    """
    fd = (_windows_fd(path, GENERIC_READ, OPEN_EXISTING, os.O_RDONLY)
          if WINDOWS else os.open(path, RO_FLAGS))
    try:
        data = os.read(fd, limit + 1)
        # efivarfs reports st_size 0 for some entries, so trust the read length.
        while len(data) <= limit:
            chunk = os.read(fd, limit + 1 - len(data))
            if not chunk:
                return data
            data += chunk
        raise ValueError(f"{path}: exceeds {limit} byte limit")
    finally:
        os.close(fd)


def require_empty_output_dir(path: str) -> None:
    """Allow a missing or empty directory, refusing unsafe existing paths."""
    if WINDOWS:
        absolute = os.path.abspath(path)
        drive, tail = os.path.splitdrive(absolute)
        current = drive + os.sep
        for part in tail.split(os.sep):
            if not part:
                continue
            current = os.path.join(current, part)
            if not os.path.lexists(current):
                return
            if os.path.islink(current) or os.path.isjunction(current):
                raise PermissionError(f"{path}: output path contains a reparse point")
            if not os.path.isdir(current):
                raise PermissionError(f"{path}: output path contains a non-directory")
        if os.listdir(absolute):
            raise FileExistsError(f"{path}: output directory is not empty")
        return

    _refuse_protected_root(path)
    parts = os.path.abspath(path).split(os.sep)
    dir_fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts:
            if not part:
                continue
            try:
                next_fd = os.open(
                    part, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC,
                    dir_fd=dir_fd)
            except FileNotFoundError:
                return
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise PermissionError(
                        f"{path}: output path contains a symlink or non-directory") from exc
                raise
            os.close(dir_fd)
            dir_fd = next_fd
        if os.fstat(dir_fd).st_uid != os.getuid():
            raise PermissionError(f"{path}: output directory owned by another user")
        if os.listdir(dir_fd):
            raise FileExistsError(f"{path}: output directory is not empty")
    finally:
        os.close(dir_fd)


def _refuse_protected_root(path: str) -> None:
    """Refuse any output destination that resolves under the kernel firmware
    tree (/sys/firmware), before any mutation such as mkdir, chmod, truncate or
    a payload write. Compares path components of the resolved real path, so
    relative paths, `..`, and symlink aliases that land in the firmware tree
    are all caught. POSIX only; the Windows tree has no such location.
    """
    if WINDOWS:
        return
    parts = os.path.realpath(os.path.abspath(path)).split(os.sep)
    if parts[:3] == ["", "sys", "firmware"]:
        raise PermissionError(f"{path}: writing under /sys/firmware is refused")


def _write_all(fd: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(fd, remaining)
        if written == 0:
            raise OSError("zero-byte write")
        remaining = remaining[written:]


def _nofollow_parent_fd(path: str) -> int:
    """POSIX: open the directory that will contain `path`, refusing to traverse
    any symlink on the way. Walks the absolute path's directory components from
    the root, opening each with O_NOFOLLOW|O_DIRECTORY, so a symlinked component
    at ANY depth -- not just the immediate parent -- raises rather than
    redirecting the write. The parent directory must already exist. Returns a
    dir fd the caller must close; final operations are anchored to it with
    dir_fd= so no path is re-resolved after this check.
    """
    parent = os.path.dirname(os.path.abspath(path))
    dir_fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parent.split(os.sep):
            if not part:
                continue
            try:
                nxt = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
                              | os.O_CLOEXEC, dir_fd=dir_fd)
            except OSError as exc:
                # ELOOP: a symlink refused by O_NOFOLLOW. ENOTDIR: O_DIRECTORY on
                # a symlink (kernel reports the leaf isn't a dir) or a real file
                # standing in for a directory. Either way, refuse to traverse it.
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise PermissionError(
                        f"{path}: output path traverses a symlinked or non-directory "
                        "component; refusing to follow") from exc
                raise
            os.close(dir_fd)
            dir_fd = nxt
        return dir_fd
    except BaseException:
        os.close(dir_fd)
        raise


def private_dir(path: str) -> str:
    """Create a directory accessible only by its owner.

    POSIX: refuses a destination resolving under /sys/firmware, a final
    symlink or one anywhere in the ancestor chain, and a directory owned by
    another user. Both the create and the re-tighten are anchored to a parent
    descriptor opened with no-follow on every component, so a swapped symlink
    -- at any depth -- cannot be followed. A new directory is created 0700; an
    existing one is re-tightened to 0700 through its own descriptor.
    """
    if WINDOWS:
        # Create the sensitive directory itself with the owner-only descriptor in
        # place (no inherited-DACL window). Non-sensitive ancestors may pre-exist
        # or be made normally; ERROR_ALREADY_EXISTS means a prior step made it and
        # the read-back below still proves it private.
        parent = os.path.dirname(os.path.normpath(path))
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        sec_attr, _keep = _private_security_attributes(_token_user_sid())
        create_dir = _dll("kernel32").CreateDirectoryW
        create_dir.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p]
        create_dir.restype = ctypes.c_int32
        if not create_dir(path, ctypes.byref(sec_attr)):
            error = ctypes.get_last_error()
            if error != ERROR_ALREADY_EXISTS:
                raise ctypes.WinError(error)
        handle = _open_windows_handle(path, 0, OPEN_EXISTING, directory=True)
        try:
            _set_windows_private_acl(path)
        finally:
            _close_windows_handle(handle)
    else:
        _refuse_protected_root(path)
        parent = os.path.dirname(os.path.abspath(path))
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        name = os.path.basename(os.path.normpath(path))
        parent_fd = _nofollow_parent_fd(path)
        try:
            try:
                dir_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
                                 | os.O_CLOEXEC, dir_fd=parent_fd)
            except FileNotFoundError:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise PermissionError(
                        f"{path}: output directory is a symlink or not a directory; "
                        "refusing to follow") from exc
                raise
            else:
                try:
                    if os.fstat(dir_fd).st_uid != os.getuid():
                        raise PermissionError(
                            f"{path}: output directory owned by another user; refusing")
                    os.fchmod(dir_fd, 0o700)
                finally:
                    os.close(dir_fd)
        finally:
            os.close(parent_fd)
    return path


def write_private(path: str, data: bytes) -> None:
    """Write `data` to `path` with owner-only permissions, safely.

    POSIX: the file is opened without truncation and the descriptor is
    inspected before any permission or content change - the destination must
    not resolve under /sys/firmware, no directory in its path may be a symlink
    (checked with a no-follow walk anchored to a parent descriptor), and the
    opened object must be a regular, non-hard-linked file owned by the caller.
    Only then is it fchmod'd 0600 (closing the 0644 overwrite window) and
    truncated through the same descriptor. A final-component symlink raises
    ELOOP at open.
    """
    if WINDOWS:
        fd = _windows_fd(path, GENERIC_WRITE, OPEN_ALWAYS, os.O_WRONLY)
        try:
            _set_windows_private_acl(path)
            os.ftruncate(fd, 0)
            _write_all(fd, data)
        finally:
            os.close(fd)
        return
    _refuse_protected_root(path)
    name = os.path.basename(os.path.normpath(path))
    parent_fd = _nofollow_parent_fd(path)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"{path}: not a regular file; refusing to write")
        if st.st_nlink > 1:
            raise PermissionError(f"{path}: hard-linked; refusing to write")
        if st.st_uid != os.getuid():
            raise PermissionError(f"{path}: owned by another user; refusing to write")
        os.fchmod(fd, 0o600)
        os.ftruncate(fd, 0)
        _write_all(fd, data)
    finally:
        os.close(fd)
