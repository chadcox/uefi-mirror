"""Runs under pytest, or standalone: `python3 tests/test_safety.py`.
No root, never touches the host's real efivarfs."""

import ast
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

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
            continue
        assert not findings, "; ".join(f"{path}:{line}: {message}"
                                       for line, message in findings)


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
                assert exc.errno == 40, exc  # ELOOP
            return
        target = os.path.join(d, "real")
        open(target, "wb").write(b"\x07\x00\x00\x00payload")
        link = os.path.join(d, "link")
        os.symlink(target, link)
        try:
            safety.read_bounded(link)
            raise AssertionError("symlink was followed")
        except OSError as exc:
            assert exc.errno == 40, exc  # ELOOP


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
