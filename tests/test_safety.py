"""Runs under pytest, or standalone: `python3 tests/test_safety.py`.
No root, never touches the host's real efivarfs."""

import ast
import errno
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import types

import fixtures

SRC = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from uefi_mirror import cli, safety  # noqa: E402
from uefi_mirror.collectors import efivarfs  # noqa: E402

PROD_FILES = [p for p in SRC.rglob("*.py")]

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _run_cli(*args, check=False):
    """Run the CLI in a subprocess with deterministic output.

    Rich decides it is on a colour terminal when it sees GITHUB_ACTIONS, and
    then splices escape codes into option names (`--output` renders as
    `\x1b[1;36m-\x1b[0m\x1b[1;36m-output\x1b[0m`), which breaks plain text
    assertions on CI but not locally. Pin the width, ask for no colour, and
    strip anything that survives.
    """
    env = {**os.environ, "PYTHONPATH": str(SRC), "COLUMNS": "200",
           "NO_COLOR": "1", "TERM": "dumb"}
    env.pop("FORCE_COLOR", None)
    proc = subprocess.run([sys.executable, "-m", "uefi_mirror.cli", *args],
                          capture_output=True, text=True, check=check, env=env)
    proc.stdout = ANSI.sub("", proc.stdout)
    proc.stderr = ANSI.sub("", proc.stderr)
    return proc

# ---------------------------------------------------------------- static scans

MUTATING_CALLS = {
    "os.replace", "os.rename", "os.remove", "os.unlink", "os.mkdir", "os.makedirs",
    "os.rmdir", "os.removedirs", "os.chmod", "os.chown", "os.link", "os.symlink",
    "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree", "shutil.move",
    "shutil.rmtree",
}
PATH_MUTATORS = {
    "write_bytes", "write_text", "unlink", "rename", "replace", "mkdir", "rmdir",
    "touch", "chmod", "symlink_to", "hardlink_to",
}
FIRMWARE_TOOLS = {"efibootmgr", "flashrom", "chipsec_util", "fwupdtool", "fwupdmgr"}
# Windows firmware setters reached through ctypes bypass the AST call scan
# (they surface as getattr/attribute access, not a recognised call name), so
# they are caught by a plain symbol scan instead.
FIRMWARE_SETTER_SYMBOLS = (
    "SetFirmwareEnvironmentVariableW", "SetFirmwareEnvironmentVariableExW",
    "SetFirmwareEnvironmentVariableA", "NtSetSystemEnvironmentValueEx",
)
# The intended output mutations in safety.py; anything else there is a finding.
SAFETY_ALLOWED_MUTATIONS = ("os.makedirs", "os.mkdir", "writing os.open")


def _call_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _literal(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


class WriteVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings = []

    def visit_Call(self, node):
        name = _call_name(node.func)
        mode = None
        if name in {"open", "builtins.open", "Path.open", "pathlib.Path.open"}:
            if len(node.args) > 1:
                mode = _literal(node.args[1])
            mode = next((_literal(k.value) for k in node.keywords if k.arg == "mode"), mode)
            if mode and any(char in mode for char in "wax+"):
                self.findings.append((node.lineno, f"writing {name} mode {mode!r}"))
        elif name == "os.open":
            flags = ast.unparse(node.args[1]) if len(node.args) > 1 else ""
            if any(flag in flags for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC")):
                self.findings.append((node.lineno, f"writing os.open flags {flags}"))
        elif name in MUTATING_CALLS or name.rsplit(".", 1)[-1] in PATH_MUTATORS:
            self.findings.append((node.lineno, f"filesystem mutation {name}"))
        elif name in {"subprocess.run", "subprocess.call", "subprocess.Popen",
                      "subprocess.check_call", "subprocess.check_output"} and node.args:
            command = node.args[0]
            values = []
            if isinstance(command, (ast.List, ast.Tuple)):
                values = [_literal(value) for value in command.elts]
            elif _literal(command):
                values = _literal(command).split()
            executable = os.path.basename(values[0]) if values and values[0] else ""
            if executable in FIRMWARE_TOOLS and "--version" not in values:
                self.findings.append((node.lineno, f"firmware tool invocation {executable}"))
        self.generic_visit(node)


def _scan(source):
    visitor = WriteVisitor()
    visitor.visit(ast.parse(source))
    return visitor.findings


def test_production_mutation_is_confined_to_safety_helpers():
    for path in PROD_FILES:
        findings = _scan(path.read_text())
        if path.name == "safety.py":
            # Not a blanket skip: safety.py may only contain the known output
            # helpers. A stray os.replace or a new firmware setter still fails.
            unexpected = [(line, message) for line, message in findings
                          if not any(a in message for a in SAFETY_ALLOWED_MUTATIONS)]
            assert not unexpected, "; ".join(f"{path}:{line}: {message}"
                                             for line, message in unexpected)
            continue
        assert not findings, "; ".join(f"{path}:{line}: {message}"
                                       for line, message in findings)


def test_no_firmware_setter_symbol_in_production():
    for path in PROD_FILES:
        text = path.read_text()
        for symbol in FIRMWARE_SETTER_SYMBOLS:
            assert symbol not in text, f"{path}: firmware setter {symbol}"


def test_safe_component_rejects_traversal_and_reserved():
    for good in ("Setup-ec87d643-eba4-4bb5-a1e5-3f3e36b20da9", "Boot0001", "a.b"):
        assert safety.safe_component(good), good
    for bad in ("", "..", ".", "a/b", "a\\b", "a:b", "a*b", "a?b", "a|b",
                "a\x00b", "con", "NUL", "COM1", "LPT9", "AUX.txt", "trail.",
                "trail ", "x" * 256):
        assert not safety.safe_component(bad), bad


def test_ast_guard_detects_every_banned_api_family():
    examples = [
        "open('x', 'wb')", "Path('x').write_text('x')", "os.replace('a', 'b')",
        "os.rename('a', 'b')", "shutil.copy2('a', 'b')", "os.unlink('x')",
        "subprocess.run(['flashrom', '-w', 'bios.bin'])",
        "os.open('x', os.O_WRONLY | os.O_CREAT)",
    ]
    for source in examples:
        assert _scan(source), source


def test_no_sys_firmware_path_is_ever_written():
    for path in PROD_FILES:
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if "/sys/firmware" in line:
                assert "O_WRONLY" not in line and "open(" not in line.replace("os.open", ""), \
                    f"{path}:{lineno}: {line.strip()}"


def test_read_flags_are_hardened():
    if os.name != "nt":
        assert safety.RO_FLAGS & os.O_NOFOLLOW
        assert safety.RO_FLAGS & os.O_CLOEXEC
    assert safety.RO_FLAGS & (os.O_WRONLY | os.O_RDWR) == 0


def test_cli_exposes_no_mutating_command():
    out = _run_cli("--help", check=True).stdout
    for word in ("set", "write", "restore", "flash", "unlock", "erase", "modify"):
        assert not re.search(rf"^\s+{word}\b", out, re.M | re.I), f"mutating command: {word}"

# ---------------------------------------------------------------- behaviour

def test_symlink_is_refused():
    with tempfile.TemporaryDirectory() as d:
        if os.name == "nt":
            target = os.path.join(d, "real")
            link = os.path.join(d, "link")
            os.makedirs(target)
            subprocess.run(["cmd", "/c", "mklink", "/J", link, target],
                           check=True, capture_output=True)
            try:
                safety.private_dir(link)
                raise AssertionError("directory junction was followed")
            except OSError as exc:
                assert exc.errno == errno.ELOOP, exc
            return
        target = os.path.join(d, "real")
        open(target, "wb").write(b"\x07\x00\x00\x00payload")
        link = os.path.join(d, "link")
        os.symlink(target, link)
        try:
            safety.read_bounded(link)
            raise AssertionError("symlink was followed")
        except OSError as exc:
            assert exc.errno == errno.ELOOP, exc


def test_oversize_read_is_refused():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "big")
        open(p, "wb").write(b"A" * 100)
        try:
            safety.read_bounded(p, limit=50)
            raise AssertionError("oversize file accepted")
        except ValueError:
            pass


def test_output_permissions_are_private():
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "snap")
        os.makedirs(out)
        os.chmod(out, 0o777)
        safety.private_dir(out)
        if os.name == "nt":
            assert safety._windows_acl_is_private(out)
        else:
            assert oct(os.stat(out).st_mode & 0o777) == "0o700"
        f = os.path.join(out, "x")
        safety.write_private(f, b"secret")
        if os.name == "nt":
            assert safety._windows_acl_is_private(f)
        else:
            assert oct(os.stat(f).st_mode & 0o777) == "0o600"


def test_private_write_retries_partial_os_writes():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "partial")
        real_write = os.write
        calls = []

        def partial(fd, data):
            calls.append(len(data))
            return real_write(fd, data[:2])

        safety.os.write = partial
        try:
            safety.write_private(path, b"abcdef")
        finally:
            safety.os.write = real_write
        assert open(path, "rb").read() == b"abcdef"
        assert len(calls) == 3


def test_windows_acl_failure_refuses_before_writing():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "refused")
        originals = safety.WINDOWS, safety._windows_fd, safety._set_windows_private_acl
        safety.WINDOWS = True
        safety._windows_fd = lambda *_args: os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)

        def refuse(_path):
            raise PermissionError("ACL not private")

        safety._set_windows_private_acl = refuse
        try:
            try:
                safety.write_private(path, b"secret")
                raise AssertionError("write continued after ACL failure")
            except PermissionError:
                pass
            assert open(path, "rb").read() == b""
        finally:
            safety.WINDOWS, safety._windows_fd, safety._set_windows_private_acl = originals


def test_cli_rejects_negative_limits():
    proc = _run_cli("schema", "missing.CAP", "--limit", "-1")
    assert proc.returncode == 2
    assert "Invalid value" in proc.stderr


def test_html_export_keeps_all_settings_and_private_permissions():
    with tempfile.TemporaryDirectory() as directory:
        tmp_path = pathlib.Path(directory)
        image = tmp_path / "BIOS.CAP"
        image.write_bytes(fixtures.build_capsule())
        efivars = tmp_path / "efivars"
        efivars.mkdir()
        payload = bytearray(0x100)
        payload[0x90] = 1
        (efivars / f"Setup-{fixtures.VARSTORE_GUID}").write_bytes(
            b"\x07\x00\x00\x00" + payload)
        output = tmp_path / "bios.html"
        proc = _run_cli(
            "export", str(image), "--efivars", str(efivars),
            "--format", "html", "--output", str(output),
            "--grep", "does not match", "--changed-only", "--visible-only",
            "--include-inactive")

        assert proc.returncode == 0, proc.stderr
        html = output.read_text()
        data = json.loads(re.search(
            r'<script id="uefi-data" type="application/json">(.*?)</script>',
            html, re.S).group(1))
        filters = json.loads(re.search(
            r'<script id="uefi-filters" type="application/json">(.*?)</script>',
            html, re.S).group(1))
        assert len(data["settings"]) == 1
        assert filters == {"grep": "does not match", "changed_only": True,
                           "visible_only": True, "include_inactive": True}
        assert data["image"]["filename"] == "BIOS.CAP"
        if os.name == "nt":
            assert safety._windows_acl_is_private(str(output))
        else:
            assert output.stat().st_mode & 0o777 == 0o600


def test_html_export_requires_output_before_reading_image():
    proc = _run_cli("export", "missing.CAP", "--format", "html")
    assert proc.returncode == 2
    assert "--output is required when --format html" in proc.stderr


def test_output_file_symlink_is_refused():
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "target")
        open(target, "wb").write(b"original")
        os.chmod(target, 0o644)
        link = os.path.join(d, "link")
        os.symlink(target, link)
        try:
            safety.write_private(link, b"secret")
            raise AssertionError("symlinked output file was written")
        except OSError:
            pass
        assert open(target, "rb").read() == b"original"
        assert oct(os.stat(target).st_mode & 0o777) == "0o644"


def test_output_dir_symlink_is_refused():
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "target")
        os.makedirs(target)
        open(os.path.join(target, "f"), "wb").write(b"x")
        os.chmod(target, 0o755)
        link = os.path.join(d, "link")
        os.symlink(target, link)
        try:
            safety.private_dir(link)
            raise AssertionError("symlinked output dir was used")
        except PermissionError:
            pass
        # The target must not have been re-tightened or written into.
        assert oct(os.stat(target).st_mode & 0o777) == "0o755"
        assert open(os.path.join(target, "f"), "rb").read() == b"x"


def test_symlinked_parent_dir_cannot_redirect_output():
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory() as d:
        elsewhere = os.path.join(d, "elsewhere")
        os.makedirs(elsewhere)
        output = os.path.join(d, "output")
        os.makedirs(output)
        raw = os.path.join(output, "raw-variables")
        os.symlink(elsewhere, raw)
        path = os.path.join(raw, "Var")
        try:
            safety.write_private(path, b"data")
            raise AssertionError("write redirected through symlinked parent dir")
        except PermissionError:
            pass
        assert not os.path.exists(os.path.join(elsewhere, "Var"))
        assert not os.path.exists(path)


def test_symlinked_grandparent_dir_cannot_redirect_output():
    """A symlink above the immediate parent must also be refused: the no-follow
    walk checks every ancestor component, not just the leaf's parent."""
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory() as d:
        elsewhere = os.path.join(d, "elsewhere")
        os.makedirs(os.path.join(elsewhere, "real-parent"))
        link = os.path.join(d, "output")
        os.symlink(elsewhere, link)  # a symlinked grandparent of the file
        path = os.path.join(link, "real-parent", "Var")
        try:
            safety.write_private(path, b"data")
            raise AssertionError("write redirected through symlinked grandparent")
        except PermissionError:
            pass
        assert not os.path.exists(os.path.join(elsewhere, "real-parent", "Var"))


def test_symlinked_grandparent_dir_cannot_redirect_dir_creation():
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory() as d:
        elsewhere = os.path.join(d, "elsewhere")
        os.makedirs(elsewhere)
        link = os.path.join(d, "output")
        os.symlink(elsewhere, link)
        try:
            safety.private_dir(os.path.join(link, "raw-variables"))
            raise AssertionError("mkdir redirected through symlinked grandparent")
        except PermissionError:
            pass
        assert not os.path.exists(os.path.join(elsewhere, "raw-variables"))


def test_hardlinked_output_is_refused():
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory() as d:
        real = os.path.join(d, "real")
        open(real, "wb").write(b"original")
        link = os.path.join(d, "link")
        os.link(real, link)
        try:
            safety.write_private(link, b"data")
            raise AssertionError("hard-linked output was written")
        except PermissionError:
            pass
        assert open(real, "rb").read() == b"original"


def test_existing_file_is_tightened_before_payload_write():
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "out")
        open(path, "wb").write(b"old-content-that-is-longer")
        os.chmod(path, 0o644)
        observed = []
        real_write = os.write

        def checking(fd, data):
            observed.append(os.fstat(fd).st_mode & 0o777)
            return real_write(fd, data)

        safety.os.write = checking
        try:
            safety.write_private(path, b"new")
        finally:
            safety.os.write = real_write
        assert observed, "no payload write was made"
        assert all(mode == 0o600 for mode in observed), observed
        assert open(path, "rb").read() == b"new"
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"


def test_hardening_failure_leaves_contents_intact():
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "out")
        open(path, "wb").write(b"keep-me")
        os.chmod(path, 0o644)
        real_fchmod = os.fchmod

        def refuse(_fd, _mode):
            raise PermissionError("fchmod blocked")

        safety.os.fchmod = refuse
        try:
            try:
                safety.write_private(path, b"secret")
                raise AssertionError("write proceeded despite hardening failure")
            except PermissionError:
                pass
            assert open(path, "rb").read() == b"keep-me"
        finally:
            safety.os.fchmod = real_fchmod


def test_other_user_output_is_refused():
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "out")
        open(path, "wb").write(b"existing")
        real_getuid = os.getuid
        safety.os.getuid = lambda: 999999
        try:
            try:
                safety.write_private(path, b"secret")
                raise AssertionError("other-user file was written")
            except PermissionError:
                pass
            assert open(path, "rb").read() == b"existing"
        finally:
            safety.os.getuid = real_getuid


def test_non_regular_file_is_refused():
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "out")
        open(path, "wb").write(b"existing")
        real_fstat = os.fstat

        class _FakeStat:
            st_mode = stat.S_IFCHR  # a character device, not a regular file
            st_nlink = 1
            st_uid = os.getuid()

        safety.os.fstat = lambda _fd: _FakeStat()
        try:
            try:
                safety.write_private(path, b"secret")
                raise AssertionError("non-regular file was written")
            except PermissionError:
                pass
            assert open(path, "rb").read() == b"existing"
        finally:
            safety.os.fstat = real_fstat


def test_overwrite_shorter_leaves_no_old_suffix():
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "out")
        open(path, "wb").write(b"abcdefghij")
        os.chmod(path, 0o600)
        safety.write_private(path, b"xyz")
        assert open(path, "rb").read() == b"xyz"
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"
        fresh = os.path.join(d, "fresh")
        safety.write_private(fresh, b"data")
        assert open(fresh, "rb").read() == b"data"
        assert oct(os.stat(fresh).st_mode & 0o777) == "0o600"


def test_protected_firmware_root_is_refused():
    if os.name == "nt":
        return
    # The gate is pure string logic on the resolved path: no I/O runs, which is
    # what proves a firmware destination is refused before any mkdir/open/
    # chmod/truncate could happen.
    for bad in ("/sys/firmware/efi/vars/evil", "/sys/firmware",
                "/sys/../sys/firmware/efi/x"):
        try:
            safety._refuse_protected_root(bad)
            raise AssertionError(f"protected path accepted: {bad}")
        except PermissionError:
            pass
    # Adjacent components must not be refused (component-boundary check).
    safety._refuse_protected_root("/sys/firmware-evil/x")
    safety._refuse_protected_root("/other/sys/firmware/x")


def test_protected_firmware_symlink_alias_is_refused():
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory() as d:
        alias = os.path.join(d, "alias")
        os.symlink("/sys/firmware", alias)
        try:
            safety._refuse_protected_root(os.path.join(alias, "efi", "evil"))
            raise AssertionError("symlink alias into /sys/firmware accepted")
        except PermissionError:
            pass


def test_cli_refuses_symlinked_output_dir():
    with tempfile.TemporaryDirectory() as directory:
        tmp = pathlib.Path(directory)
        efivars = tmp / "efivars"
        efivars.mkdir()
        (efivars / GOOD).write_bytes(b"\x07\x00\x00\x00\x01\x02\x03")
        target = tmp / "target"
        os.makedirs(target)
        link = tmp / "snap"
        os.symlink(str(target), str(link))
        proc = _run_cli("snapshot", "--output", str(link), "--efivars", str(efivars))
        assert proc.returncode != 0
        assert "Traceback" not in proc.stderr
        assert "refused output" in (proc.stderr + proc.stdout)
        # The symlink target must not have been written into.
        assert not os.path.exists(os.path.join(target, "raw-variables"))
        assert not os.path.exists(os.path.join(target, "manifest.json"))

# ---------------------------------------------------------------- network

_HTTPS_HOSTS = frozenset({"www.asus.com"})


class _HttpResponse:
    def __init__(self, data=b"ok", *, headers=None, url="https://www.asus.com/final",
                 on_read=None):
        self.data = data
        self.headers = headers or {}
        self.url = url
        self.on_read = on_read
        self.position = 0
        self.reads = 0
        self.closed = False
        self.socket_timeouts = []
        sock = types.SimpleNamespace(settimeout=self.socket_timeouts.append)
        self.fp = types.SimpleNamespace(raw=types.SimpleNamespace(_sock=sock))

    def geturl(self):
        return self.url

    def read(self, size=-1):
        self.reads += 1
        if self.on_read:
            self.on_read()
        if size < 0:
            raise AssertionError("unbounded HTTP read")
        chunk = self.data[self.position:self.position + size]
        self.position += len(chunk)
        return chunk

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class _HttpOpener:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


def _read_https(response, *, limit=10, budget=None):
    opener = _HttpOpener(response)
    handlers = []
    real_build_opener = safety.urllib.request.build_opener

    def build_opener(*args):
        handlers.extend(args)
        return opener

    safety.urllib.request.build_opener = build_opener
    try:
        result = safety.read_https(
            "https://www.asus.com/start", limit, _HTTPS_HOSTS, stage="metadata",
            budget=budget or safety.HttpBudget())
        return result, opener, handlers
    finally:
        safety.urllib.request.build_opener = real_build_opener


def test_https_url_policy_refuses_unapproved_destinations_before_opening():
    bad = (
        "http://www.asus.com/x",
        "https://user@www.asus.com/x",
        "https://www.asus.com:444/x",
        "https://www.asus.com:bad/x",
        "https://www.asus.com.evil.example/x",
        "https://www.asus.com./x",
        "https://localhost/x",
        "https://127.0.0.1/x",
        "https://[::1]/x",
        "https://www.asus.com/x#fragment",
        "https://www.asus.com/a b",
        "https://www.asus.com/café",
    )
    real_build_opener = safety.urllib.request.build_opener
    safety.urllib.request.build_opener = lambda *_args: (_ for _ in ()).throw(
        AssertionError("refused destination was opened"))
    try:
        for url in bad:
            try:
                safety.read_https(url, 10, _HTTPS_HOSTS, stage="metadata",
                                  budget=safety.HttpBudget())
                raise AssertionError(f"unsafe URL accepted: {url}")
            except ValueError:
                pass
    finally:
        safety.urllib.request.build_opener = real_build_opener


def test_https_reader_disables_proxies_sets_headers_and_closes_response():
    response = _HttpResponse(b"data", headers={"Content-Length": "4"})
    result, opener, handlers = _read_https(response)

    request, timeout = opener.requests[0]
    proxies = [handler for handler in handlers
               if isinstance(handler, safety.urllib.request.ProxyHandler)]
    assert result == safety.HttpResult(b"data", "https://www.asus.com/final")
    assert proxies and proxies[0].proxies == {}
    assert request.get_header("Accept-encoding") == "identity"
    assert request.get_header("User-agent") == f"uefi-mirror/{safety.__version__}"
    assert timeout == safety.HTTP_TIMEOUT_SECONDS
    assert response.socket_timeouts
    assert max(response.socket_timeouts) <= safety.HTTP_TIMEOUT_SECONDS
    assert response.closed


def test_https_reader_enforces_declared_actual_and_encoding_limits():
    cases = (
        (_HttpResponse(b"", headers={"Content-Length": "11"}), 10, "byte limit"),
        (_HttpResponse(b"1234"), 3, "byte limit"),
        (_HttpResponse(b"abc", headers={"Content-Length": "4"}), 10, "expected 4"),
        (_HttpResponse(b"abc", headers={"Content-Length": "nope"}), 10,
         "invalid Content-Length"),
        (_HttpResponse(b"abc", headers={"Content-Encoding": "gzip"}), 10,
         "unsupported Content-Encoding"),
        (_HttpResponse(b"abc", headers={"Content-Length": 3}), 10,
         "invalid Content-Length"),
        (_HttpResponse(b"abc", headers={"Content-Encoding": 7}), 10,
         "invalid Content-Encoding"),
    )
    for response, limit, message in cases:
        try:
            _read_https(response, limit=limit)
            raise AssertionError(f"unsafe response accepted: {message}")
        except ValueError as exc:
            assert message in str(exc), exc
        assert response.closed
    assert cases[0][0].reads == 0


def test_https_redirects_are_validated_bounded_and_not_read():
    budget = safety.HttpBudget(requests=1)
    handler = safety._CheckedRedirectHandler(_HTTPS_HOSTS, budget, "metadata")
    destination = _HttpResponse()
    parent = _HttpOpener(destination)
    handler.add_parent(parent)

    request = safety.urllib.request.Request("https://www.asus.com/start")
    redirect = _HttpResponse()
    result = handler.http_error_302(
        request, redirect, 302, "Found", {"Location": "/next"})
    assert result is destination
    assert redirect.closed and redirect.reads == 0
    assert parent.requests[0][0].full_url == "https://www.asus.com/next"
    assert budget.requests == 1  # Redirect hops do not consume the request budget.

    for location in ("http://www.asus.com/down", "https://evil.example/x", 7, None):
        refused = _HttpResponse()
        try:
            handler.http_error_302(
                request, refused, 302, "Found",
                {"Location": location} if location is not None else {})
            raise AssertionError(f"unsafe redirect accepted: {location}")
        except ValueError:
            pass
        assert refused.closed
    assert len(parent.requests) == 1

    request._uefi_redirects = safety.MAX_REDIRECTS
    refused = _HttpResponse()
    try:
        handler.http_error_302(
            request, refused, 302, "Found", {"Location": "/loop"})
        raise AssertionError("redirect limit was ignored")
    except ValueError as exc:
        assert "redirect limit" in str(exc)
    assert refused.closed and len(parent.requests) == 1


def test_https_reader_refuses_an_unapproved_final_url_and_closes_response():
    response = _HttpResponse(url="https://evil.example/final")
    try:
        _read_https(response)
        raise AssertionError("unapproved final URL accepted")
    except ValueError as exc:
        assert "final URL refused" in str(exc)
    assert response.closed and response.reads == 0


def test_https_reader_enforces_request_and_whole_fetch_deadlines():
    exhausted = safety.HttpBudget(requests=safety.MAX_HTTP_REQUESTS)
    try:
        _read_https(_HttpResponse(), budget=exhausted)
        raise AssertionError("request budget was ignored")
    except ValueError as exc:
        assert "request limit" in str(exc)

    now = [100.0]
    real_monotonic = safety.time.monotonic
    safety.time.monotonic = lambda: now[0]
    response = _HttpResponse(b"ab", on_read=lambda: now.__setitem__(0, 281.0))
    try:
        _read_https(response, budget=safety.HttpBudget(deadline=280.0))
        raise AssertionError("whole fetch deadline was ignored")
    except ValueError as exc:
        assert "timed out" in str(exc)
    finally:
        safety.time.monotonic = real_monotonic
    assert response.closed


def test_https_reader_reports_http_and_socket_failures_without_bodies():
    error_body = _HttpResponse(b"do not read me")
    http_error = safety.urllib.error.HTTPError(
        "https://www.asus.com/start", 429, "rate limited", {}, error_body)
    try:
        _read_https(http_error)
        raise AssertionError("HTTP error accepted")
    except ValueError as exc:
        assert "HTTP 429" in str(exc)
    assert error_body.closed and error_body.reads == 0

    timeout = safety.urllib.error.URLError(TimeoutError("slow"))
    try:
        _read_https(timeout)
        raise AssertionError("timeout accepted")
    except ValueError as exc:
        assert "timed out" in str(exc)

    tls = safety.urllib.error.URLError(
        safety.ssl.SSLCertVerificationError("untrusted certificate"))
    try:
        _read_https(tls)
        raise AssertionError("TLS verification failure accepted")
    except ValueError as exc:
        assert "TLS certificate verification failed" in str(exc)

# ---------------------------------------------------------------- parsing

GOOD = "Setup-ec87d643-eba4-4bb5-a1e5-3f3e36b20da9"


def test_filename_parsing():
    assert efivarfs.parse_filename(GOOD) == ("Setup", "ec87d643-eba4-4bb5-a1e5-3f3e36b20da9")
    # A hyphenated variable name must not eat the GUID.
    assert efivarfs.parse_filename("Boot-Order-" + GOOD.split("-", 1)[1])[0] == "Boot-Order"
    for bad in ("NoGuid", "Setup-notaguid", "Setup-ec87d643-eba4-4bb5-a1e5", GOOD + "x"):
        assert efivarfs.parse_filename(bad) is None, bad


def test_truncated_variable_is_recorded_not_raised():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, GOOD), "wb").write(b"\x07\x00")  # 2 bytes, no payload
        var = efivarfs.read_variable(d, GOOD)
        assert var.error and var.payload is None


def test_end_to_end_on_a_fake_efivarfs():
    with tempfile.TemporaryDirectory() as d:
        fake = os.path.join(d, "efivars")
        os.makedirs(fake)
        open(os.path.join(fake, GOOD), "wb").write(b"\x07\x00\x00\x00\x01\x02\x03")
        # Same name, different GUID: both must survive.
        other = "Setup-4034591c-48ea-4cdc-864f-e7cb61cfd0f2"
        open(os.path.join(fake, other), "wb").write(b"\x06\x00\x00\x00\xff")
        open(os.path.join(fake, "garbage"), "wb").write(b"nope")
        if os.name != "nt":
            os.symlink("/etc/passwd", os.path.join(fake, "Evil-" + GOOD.split("-", 1)[1]))

        out = os.path.join(d, "snap")
        cli.snapshot.__wrapped__(output=out, efivars=fake) if hasattr(
            cli.snapshot, "__wrapped__") else cli.snapshot(output=out, efivars=fake)

        manifest = json.load(open(os.path.join(out, "manifest.json")))
        names = {(v["name"], v["guid"]): v for v in manifest["variables"]}
        assert len(names) == 2, names  # garbage skipped, symlink not a regular file
        assert names[("Setup", "ec87d643-eba4-4bb5-a1e5-3f3e36b20da9")]["payload_size"] == 3
        assert names[("Setup", "4034591c-48ea-4cdc-864f-e7cb61cfd0f2")]["payload_size"] == 1
        assert not os.path.exists(os.path.join(out, "raw-variables", "Evil-" + GOOD.split("-", 1)[1]))
        assert open(os.path.join(out, "raw-variables", GOOD), "rb").read() == b"\x01\x02\x03"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    sys.exit(1 if failures else 0)
