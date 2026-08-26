"""Read-only primitives. Nothing here may ever open a file for writing
inside /sys/firmware. Enforced by tests/test_safety.py."""

import ctypes
import errno
import os

# efivarfs vars are kernel-capped well under this; the limit is belt-and-braces
# against a hostile/buggy filesystem handing us an endless read.
MAX_VARIABLE_BYTES = 1 << 20
WINDOWS = os.name == "nt"

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


def _dll(name: str):
    return getattr(ctypes, "WinDLL")(name, use_last_error=True)


def _close_windows_handle(handle: int) -> None:
    close = _dll("kernel32").CloseHandle
    close.argtypes, close.restype = [ctypes.c_void_p], ctypes.c_int32
    close(handle)


def _open_windows_handle(path: str, access: int, disposition: int,
                         directory: bool = False) -> int:
    """Open the named object itself and refuse any final-component reparse point."""
    kernel32 = _dll("kernel32")
    create = kernel32.CreateFileW
    create.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                       ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    create.restype = ctypes.c_void_p
    flags = FILE_FLAG_OPEN_REPARSE_POINT | (
        FILE_FLAG_BACKUP_SEMANTICS if directory else FILE_ATTRIBUTE_NORMAL)
    handle = create(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, None,
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
    return api


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

    handle = _open_windows_handle(path, access, disposition)
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


def private_dir(path: str) -> str:
    """Create a directory accessible only by its owner."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    if WINDOWS:
        handle = _open_windows_handle(path, 0, OPEN_EXISTING, directory=True)
        try:
            _set_windows_private_acl(path)
        finally:
            _close_windows_handle(handle)
    else:
        os.chmod(path, 0o700)
    return path


def write_private(path: str, data: bytes) -> None:
    if WINDOWS:
        fd = _windows_fd(path, GENERIC_WRITE, OPEN_ALWAYS, os.O_WRONLY)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
    try:
        if WINDOWS:
            _set_windows_private_acl(path)
            os.ftruncate(fd, 0)
        remaining = memoryview(data)
        while remaining:
            written = os.write(fd, remaining)
            if written == 0:
                raise OSError("zero-byte write")
            remaining = remaining[written:]
    finally:
        os.close(fd)
    if not WINDOWS:
        os.chmod(path, 0o600)
