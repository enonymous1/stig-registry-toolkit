"""Tests for the registry backends and value coercion."""

import pytest

from stig_registry_toolkit.registry import (
    FakeRegistryBackend,
    RegistryNotFoundError,
    RegistryUnavailableError,
    WinRegBackend,
    coerce_value,
    normalize_hive,
    normalize_path,
)


def test_coerce_dword_strings_and_hex():
    assert coerce_value("REG_DWORD", "0") == 0
    assert coerce_value("REG_DWORD", "42") == 42
    assert coerce_value("REG_DWORD", "0x10") == 16
    assert coerce_value("REG_DWORD", 7) == 7
    with pytest.raises(TypeError):
        coerce_value("REG_DWORD", "one")
    with pytest.raises(TypeError):
        coerce_value("REG_DWORD", True)
    with pytest.raises(TypeError):
        coerce_value("REG_SZ", 3)


def test_coerce_multi_and_binary():
    assert coerce_value("REG_MULTI_SZ", "a") == ["a"]
    assert coerce_value("REG_MULTI_SZ", ["a", "b"]) == ["a", "b"]
    assert coerce_value("REG_BINARY", "00ff") == b"\x00\xff"
    with pytest.raises(TypeError):
        coerce_value("REG_MULTI_SZ", [1])


def test_normalize_hive_and_path():
    assert normalize_hive("hkey_local_machine") == "HKEY_LOCAL_MACHINE"
    with pytest.raises(ValueError):
        normalize_hive("HKEY_NOPE")
    assert (
        normalize_path("\\Software\\Policies\\Chrome\\") == r"Software\Policies\Chrome"
    )
    with pytest.raises(ValueError):
        normalize_path("")
    with pytest.raises(ValueError):
        normalize_path(r"Software\\Chrome")


def test_fake_backend_round_trip():
    backend = FakeRegistryBackend()
    backend.write(
        "HKEY_LOCAL_MACHINE", r"SOFTWARE\Policies\Chrome", "Example", "REG_DWORD", 1
    )
    assert backend.read(
        "HKEY_LOCAL_MACHINE", r"SOFTWARE\Policies\Chrome", "Example"
    ) == (1, "REG_DWORD")
    assert backend.key_exists("HKEY_LOCAL_MACHINE", r"SOFTWARE\Policies\Chrome")
    backend.delete_value("HKEY_LOCAL_MACHINE", r"SOFTWARE\Policies\Chrome", "Example")
    with pytest.raises(RegistryNotFoundError):
        backend.read("HKEY_LOCAL_MACHINE", r"SOFTWARE\Policies\Chrome", "Example")


def test_fake_backend_create_keys_flag():
    backend = FakeRegistryBackend()
    with pytest.raises(RegistryNotFoundError):
        backend.write(
            "HKEY_LOCAL_MACHINE",
            r"SOFTWARE\Missing",
            "V",
            "REG_DWORD",
            1,
            create_keys=False,
        )
    backend.write(
        "HKEY_LOCAL_MACHINE", r"SOFTWARE\Missing", "V", "REG_DWORD", 1, create_keys=True
    )
    assert backend.read("HKEY_LOCAL_MACHINE", r"SOFTWARE\Missing", "V") == (
        1,
        "REG_DWORD",
    )


def test_fake_backend_leading_backslash_matches():
    backend = FakeRegistryBackend()
    backend.seed(
        "HKEY_LOCAL_MACHINE", r"\Software\Policies\Chrome", "Example", "REG_DWORD", 2
    )
    assert backend.read(
        "HKEY_LOCAL_MACHINE", r"Software\Policies\Chrome", "Example"
    ) == (2, "REG_DWORD")


def test_winreg_backend_unavailable_off_windows():
    # This box has no winreg module; on Windows this test's premise
    # changes, so skip there instead of asserting unavailability.
    import sys

    if sys.platform == "win32":
        pytest.skip("winreg exists on Windows")
    with pytest.raises(RegistryUnavailableError):
        WinRegBackend()
