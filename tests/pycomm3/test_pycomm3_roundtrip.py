"""End-to-end round-trip against pycomm3 — the de facto Python client for
Allen-Bradley Logix controllers — talking to the Rust port's `logix-host`
sample binary.

Our in-tree Rust tests prove the server speaks to our own `TagClient`; this
test proves it speaks the exact wire dialect pycomm3 (and by extension
Studio 5000) expects. Covers every atomic CIP type the server exposes,
including the Logix bit-string family and SHORT_STRING. Also exercises the
encap-level `ListIdentity` reply and the Class 3 connected-explicit path
(`Forward_Open` → `SendUnitData`), which is what blocks pycomm3's own
`LogixDriver.__enter__` without those services wired up.

Skipped automatically if pycomm3 is not installed. The server binary is
built via `cargo build --release -p logix-host` on first run.
"""
from __future__ import annotations

import contextlib
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

pycomm3 = pytest.importorskip("pycomm3")


REPO_ROOT = Path(__file__).resolve().parents[2]


def _bits(value: int, width: int) -> list:
    return [bool((value >> i) & 1) for i in range(width)]


# (name, initial_value, write_value). Order and names match the Rust
# `logix-host` seed set and the sibling Python port's roundtrip test.
TYPES = [
    ("TestBool",  True,       False),
    ("TestSint",  -5,         127),
    ("TestInt",   -1234,      32000),
    ("TestDint",  -1_000_000, 2_000_000_000),
    ("TestLint",  -1,         0x7FFF_FFFF_FFFF_FFFF),
    ("TestUsint", 42,         0xFF),
    ("TestUint",  0xBEEF,     0xFFFF),
    ("TestUdint", 0xDEADBEEF, 0xFFFF_FFFF),
    ("TestUlint", 1_234_567_890_123, 0xFFFF_FFFF_FFFF_FFFF),
    ("TestReal",  3.14,       -2.71828),
    ("TestLreal", 3.141592653589793, -2.718281828459045),
    ("TestByte",  _bits(0xAB, 8),   _bits(0xCD, 8)),
    ("TestWord",  _bits(0x1234, 16), _bits(0xABCD, 16)),
    # pycomm3 collapses a raw DWORD read to bit 0; we also do a `{32}`
    # full-width read below to prove the whole value was stored.
    ("TestDword", _bits(0xDEADBEEF, 32), _bits(0xCAFEBABE, 32)),
    ("TestLword", _bits(0x1234_5678_9ABC_DEF0, 64), _bits(0xFEDC_BA98_7654_3210, 64)),
]

ATOMIC_SCALARS = {"TestBool", "TestSint", "TestInt", "TestDint", "TestLint",
                  "TestUsint", "TestUint", "TestUdint", "TestUlint",
                  "TestReal", "TestLreal"}


def _grab_free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _logix_host_binary() -> Path:
    """Locate `logix-host.exe` (built via `cargo build --release -p logix-host`).

    Build it on demand so a fresh clone can run the test with just pytest.
    """
    exe = "logix-host.exe" if os.name == "nt" else "logix-host"
    path = REPO_ROOT / "target" / "release" / exe
    if not path.exists():
        subprocess.check_call(
            ["cargo", "build", "--release", "-p", "logix-host"],
            cwd=REPO_ROOT,
        )
    assert path.exists(), f"expected logix-host binary at {path}"
    return path


def _wait_reachable(port: int, timeout_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError as err:
            last_err = err
            time.sleep(0.1)
    raise AssertionError(f"logix-host did not become reachable on 127.0.0.1:{port}: {last_err}")


@pytest.fixture
def logix_host():
    port = _grab_free_port()
    binary = _logix_host_binary()
    proc = subprocess.Popen(
        [str(binary), "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_reachable(port)
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        # Drain remaining output into pytest's captured streams for easy
        # debugging when the test fails.
        out, err = proc.communicate(timeout=5)
        if out:
            sys.stdout.write(out.decode("utf-8", errors="replace"))
        if err:
            sys.stderr.write(err.decode("utf-8", errors="replace"))


def _values_match(name: str, got, expected) -> bool:
    if name == "TestBool":
        return bool(got) == bool(expected)
    if name == "TestReal":
        return abs(float(got) - float(expected)) < 1e-5
    if name == "TestLreal":
        return abs(float(got) - float(expected)) < 1e-12
    if name == "TestDword":
        # pycomm3 collapses a raw DWORD read to bit 0 — the `{32}` full-32
        # proof read below verifies the server stored the whole value.
        exp_bit = expected[0] if isinstance(expected, (list, tuple)) else bool(expected & 1)
        return bool(got) == exp_bit
    if name in ("TestByte", "TestWord", "TestLword"):
        got_list = list(got) if isinstance(got, (list, tuple)) else [got]
        exp_list = list(expected) if isinstance(expected, (list, tuple)) else [expected]
        return got_list == exp_list
    return got == expected


def test_pycomm3_every_atomic_type_round_trips(logix_host: int):
    port = logix_host
    from pycomm3 import LogixDriver
    failures: dict[str, tuple[str, dict]] = {}
    with LogixDriver(f"127.0.0.1:{port}", init_tags=True, init_program_tags=False) as plc:
        tag_names = sorted(plc.tags.keys())
        expected_names = {t[0] for t in TYPES} | {"TestShortString"}
        missing = expected_names - set(tag_names)
        assert not missing, f"pycomm3 did not enumerate: {missing}"

        for name, initial, write_val in TYPES:
            r = plc.read(name)
            if r.error:
                failures[name] = ("read-init-error", {"err": r.error})
                continue
            initial_ok = _values_match(name, r.value, initial)
            w = plc.write((name, write_val))
            if w.error:
                failures[name] = ("write-error", {"err": w.error})
                continue
            r2 = plc.read(name)
            if r2.error:
                failures[name] = ("read-back-error", {"err": r2.error})
                continue
            readback_ok = _values_match(name, r2.value, write_val)
            if not (initial_ok and readback_ok):
                failures[name] = ("mismatch", {
                    "initial": r.value, "wrote": write_val, "back": r2.value,
                    "initial_ok": initial_ok, "readback_ok": readback_ok,
                })

        # Full-32 DWORD proof read: confirms the server stored all 32 bits,
        # not just bit 0 (which is all pycomm3's default DWORD read returns).
        r = plc.read("TestDword{32}")
        want_bits = _bits(0xCAFEBABE, 32)
        if r.error or list(r.value) != want_bits:
            failures["TestDword{32}"] = ("mismatch", {"val": list(r.value) if r.value else None})

        # SHORT_STRING round-trip. Logix controllers only expose SHORT_STRING
        # on Identity attribute 7, but pycomm3's write encodes it as
        # `[length][chars]` without padding to the 81-byte slot — the server
        # pads on behalf of the client so Read_Tag replies with the stored
        # value.
        r = plc.read("TestShortString")
        if r.error:
            failures["TestShortString"] = ("read-init-error", {"err": r.error})
        else:
            w = plc.write(("TestShortString", "hello"))
            if w.error:
                failures["TestShortString"] = ("write-error", {"err": w.error})
            else:
                r2 = plc.read("TestShortString")
                if r2.error or r2.value != "hello":
                    failures["TestShortString"] = ("mismatch", {"back": r2.value})

    assert not failures, f"pycomm3 round-trip failures:\n{failures}"


# ---------------------------------------------------------------------------
# Yellow-row coverage: every tag shape the Rust port claims to support that
# pycomm3 can exercise. One assertion per row; failures are collected into a
# dict so a single run surfaces every regression.
# ---------------------------------------------------------------------------
def test_pycomm3_every_yellow_row(logix_host: int):
    port = logix_host
    from pycomm3 import LogixDriver

    failures: dict[str, tuple[str, dict]] = {}

    def check(label: str, cond: bool, detail=None) -> None:
        if not cond:
            failures[label] = ("mismatch", detail or {})

    with LogixDriver(f"127.0.0.1:{port}", init_tags=True, init_program_tags=False) as plc:
        # Row 17: 1-D array of atomics — indexed read/write.
        r = plc.read("DintArr[5]")
        check("17 DintArr[5] read", not r.error and r.value == 105,
              {"err": r.error, "val": r.value})
        w = plc.write(("DintArr[5]", 999))
        r2 = plc.read("DintArr[5]")
        check("17 DintArr[5] round-trip",
              not w.error and not r2.error and r2.value == 999,
              {"w": w.error, "r": r2.error, "back": r2.value})

        # Row 18: whole-array read via `{10}`.
        r = plc.read("DintArr{10}")
        vals = list(r.value) if r.value else None
        check("18 DintArr{10}",
              not r.error and vals is not None and vals[0] == 100 and vals[9] == 109,
              {"err": r.error, "vals": vals})

        # Rows 19 & 20: fragmented read + write of all 10 elements.
        w = plc.write(("DintArr{10}", list(range(1000, 1010))))
        r = plc.read("DintArr{10}")
        back = list(r.value) if r.value else None
        check("19-20 DintArr{10} fragmented r/w",
              not w.error and not r.error and back == list(range(1000, 1010)),
              {"w": w.error, "r": r.error, "back": back})

        # Row 21: bit of atomic DINT.
        r = plc.read("FlagsDint.1")
        check("21 FlagsDint.1 read",
              not r.error and bool(r.value) is True,
              {"err": r.error, "val": r.value})
        w = plc.write(("FlagsDint.0", True))
        r2 = plc.read("FlagsDint.0")
        check("21 FlagsDint.0 bit write",
              not w.error and not r2.error and bool(r2.value) is True,
              {"w": w.error, "r": r2.error, "back": r2.value})

        # Row 22: BOOL array (DWORD-packed) bit read + write.
        r = plc.read("Flags32[3]")
        check("22 Flags32[3] read",
              not r.error,
              {"err": r.error, "val": r.value})
        w = plc.write(("Flags32[7]", True))
        r2 = plc.read("Flags32[7]")
        check("22 Flags32[7] bit write",
              not w.error and not r2.error and bool(r2.value) is True,
              {"w": w.error, "r": r2.error, "back": r2.value})

        # Row 23: multi-dimensional array (row-major Matrix[2,3]).
        r = plc.read("Matrix[1,2]")
        check("23 Matrix[1,2] read",
              not r.error and r.value == 12,
              {"err": r.error, "val": r.value})
        w = plc.write(("Matrix[0,1]", 777))
        r2 = plc.read("Matrix[0,1]")
        check("23 Matrix[0,1] write",
              not w.error and not r2.error and r2.value == 777,
              {"w": w.error, "r": r2.error, "back": r2.value})

        # Row 24: Logix STRING UDT whole-struct round-trip.
        r = plc.read("Greeting")
        check("24 Greeting read",
              not r.error and r.value == "Hello pycomm3",
              {"err": r.error, "val": r.value})
        w = plc.write(("Greeting", "written back"))
        r2 = plc.read("Greeting")
        check("24 Greeting round-trip",
              not w.error and not r2.error and r2.value == "written back",
              {"w": w.error, "r": r2.error, "back": r2.value})

        # Row 25: STRING UDT array element write + read.
        w = plc.write(("GreetingArr[1]", "second"))
        r = plc.read("GreetingArr[1]")
        check("25 GreetingArr[1]",
              not w.error and not r.error and r.value == "second",
              {"w": w.error, "r": r.error, "val": r.value})

        # Row 26: User UDT whole-struct read (returns dict).
        r = plc.read("MotorA")
        ok = (not r.error and isinstance(r.value, dict)
              and abs(r.value["Speed"] - 3.14) < 1e-4
              and r.value["Fault"] is True
              and r.value["RunCount"] == 42)
        check("26 MotorA whole-struct", ok, {"err": r.error, "val": r.value})

        # Row 27: UDT member access (atomic members).
        r = plc.read("MotorA.Speed")
        check("27 MotorA.Speed",
              not r.error and abs(r.value - 3.14) < 1e-5,
              {"err": r.error, "val": r.value})
        r = plc.read("MotorA.RunCount")
        check("27 MotorA.RunCount",
              not r.error and r.value == 42,
              {"err": r.error, "val": r.value})
        w = plc.write(("MotorA.Speed", -1.5))
        r2 = plc.read("MotorA.Speed")
        check("27 MotorA.Speed write",
              not w.error and not r2.error and abs(r2.value - (-1.5)) < 1e-5,
              {"w": w.error, "r": r2.error, "back": r2.value})

        # Row 29: BOOL member of UDT read + write.
        r = plc.read("MotorA.Fault")
        check("29 MotorA.Fault read",
              not r.error and bool(r.value) is True,
              {"err": r.error, "val": r.value})
        w = plc.write(("MotorA.Fault", False))
        r2 = plc.read("MotorA.Fault")
        check("29 MotorA.Fault write",
              not w.error and not r2.error and bool(r2.value) is False,
              {"w": w.error, "r": r2.error, "back": r2.value})

        # Row 31: array of UDTs with member access (one path).
        w = plc.write(("MotorArr[1].Speed", 7.77))
        r = plc.read("MotorArr[1].Speed")
        check("31 MotorArr[1].Speed",
              not w.error and not r.error and abs(r.value - 7.77) < 1e-4,
              {"w": w.error, "r": r.error, "val": r.value})

        # Row 39: multi-service packet batch READ (three atomics in one MR).
        batch = plc.read("DintArr[0]", "DintArr[1]", "DintArr[2]")
        vals = [t.value for t in batch]
        errs = [t.error for t in batch]
        check("39 batch read",
              all(e is None for e in errs) and vals == [1000, 1001, 1002],
              {"errs": errs, "vals": vals})

        # Row 40: multi-service packet batch WRITE.
        res = plc.write(("DintArr[0]", 5000), ("DintArr[1]", 5001), ("DintArr[2]", 5002))
        r = plc.read("DintArr[0]", "DintArr[1]", "DintArr[2]")
        back = [t.value for t in r]
        res_errs = [t.error for t in res]
        check("40 batch write",
              all(e is None for e in res_errs) and back == [5000, 5001, 5002],
              {"res_errs": res_errs, "back": back})

    assert not failures, (
        "pycomm3 yellow-row failures:\n"
        + "\n".join(f"  {k}: {v}" for k, v in failures.items())
    )
