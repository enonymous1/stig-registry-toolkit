"""Windows Registry access behind a small backend interface.

Reads and writes always use the same registry view (64-bit by default),
so a check cannot read one view and fix another. The in-memory fake
backend exists so the check/fix engine and the CLI can be tested on
machines without a registry at all; it is never used for real fixes
unless a caller explicitly passes it in.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any

# Numeric codes match the ``winreg`` constants, so stored types compare
# equal whether they came from the real registry or the fake backend.
REG_TYPE_NAMES: dict[str, int] = {
    "REG_NONE": 0,
    "REG_SZ": 1,
    "REG_EXPAND_SZ": 2,
    "REG_BINARY": 3,
    "REG_DWORD": 4,
    "REG_DWORD_LITTLE_ENDIAN": 4,
    "REG_DWORD_BIG_ENDIAN": 5,
    "REG_LINK": 6,
    "REG_MULTI_SZ": 7,
    "REG_QWORD": 11,
    "REG_QWORD_LITTLE_ENDIAN": 11,
}

REG_TYPE_CODES: dict[int, str] = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}

HIVES = frozenset(
    {
        "HKEY_LOCAL_MACHINE",
        "HKEY_CURRENT_USER",
        "HKEY_CLASSES_ROOT",
        "HKEY_USERS",
        "HKEY_CURRENT_CONFIG",
    }
)

_HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")
_INT_RE = re.compile(r"^-?\d+$")

# Inclusive bounds for the Windows integer types. winreg rejects
# out-of-range values at write time with an opaque OverflowError, so
# the range is checked here, where the failure names the value.
_DWORD_MAX = 2**32 - 1
_QWORD_MAX = 2**64 - 1


def is_admin() -> bool:
    """True only for a genuinely elevated Windows process.

    Off Windows this is always False: there is no Windows admin
    concept to report. Callers that only care about the Windows case
    guard with ``os.name == "nt"`` instead of treating False here
    as "needs a warning on every platform".
    """
    import ctypes  # noqa: PLC0415
    import os

    if os.name != "nt":
        return False
    try:
        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return False
        return bool(windll.shell32.IsUserAnAdmin() != 0)
    except Exception:
        return False


class RegistryError(Exception):
    """Base class for registry failures."""


class RegistryUnavailableError(RegistryError):
    """The real registry backend cannot run on this platform."""


class RegistryNotFoundError(RegistryError):
    """A key or value does not exist."""


class RegistryPermissionError(RegistryError):
    """Access to a key or value was denied."""


def normalize_hive(hive: str) -> str:
    """Validate and uppercase a hive name."""
    upper = hive.strip().upper()
    if upper not in HIVES:
        raise ValueError(f"unknown registry hive: {hive!r}")
    return upper


def normalize_path(path: str) -> str:
    """Strip stray leading/trailing separators; reject empty segments."""
    cleaned = path.strip().strip("\\")
    if not cleaned:
        raise ValueError("registry path is empty")
    if "\\\\" in cleaned:
        raise ValueError(f"registry path has an empty segment: {path!r}")
    return cleaned


def coerce_value(reg_type: str, value: Any) -> Any:
    """Coerce ``value`` to the Python form for ``reg_type``.

    Numeric types accept ints and decimal/hex strings (the form the
    bundled data used to ship in). Strings stay strings, multi-strings
    become lists of strings, and binary becomes bytes. Anything else is
    rejected instead of being written to the registry in a wrong form.
    """
    upper = reg_type.upper()
    if upper not in REG_TYPE_NAMES:
        raise ValueError(f"unknown registry type: {reg_type!r}")
    if upper in (
        "REG_DWORD",
        "REG_DWORD_LITTLE_ENDIAN",
        "REG_DWORD_BIG_ENDIAN",
        "REG_QWORD",
        "REG_QWORD_LITTLE_ENDIAN",
    ):
        limit = _DWORD_MAX if "QWORD" not in upper else _QWORD_MAX
        if isinstance(value, bool):
            raise TypeError(f"{upper} value must be an int, got bool")
        if isinstance(value, int):
            parsed = value
        elif isinstance(value, str):
            text = value.strip()
            if _HEX_RE.match(text):
                parsed = int(text, 16)
            elif _INT_RE.match(text):
                parsed = int(text, 10)
            else:
                raise TypeError(f"{upper} value must be an int, got {value!r}")
        else:
            raise TypeError(f"{upper} value must be an int, got {value!r}")
        if not 0 <= parsed <= limit:
            raise ValueError(
                f"{upper} value must be between 0 and {limit}, got {parsed}"
            )
        return parsed
    if upper in ("REG_SZ", "REG_EXPAND_SZ"):
        if not isinstance(value, str):
            raise TypeError(f"{upper} value must be a string, got {value!r}")
        return value
    if upper == "REG_MULTI_SZ":
        if isinstance(value, str):
            return [value]
        if isinstance(value, (list, tuple)) and all(
            isinstance(item, str) for item in value
        ):
            return list(value)
        raise TypeError(
            f"REG_MULTI_SZ value must be a string or list of strings, got {value!r}"
        )
    if upper == "REG_BINARY":
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            try:
                return bytes.fromhex(value.strip())
            except ValueError as exc:
                raise TypeError(
                    f"REG_BINARY value must be bytes or a hex string, got {value!r}"
                ) from exc
        raise TypeError(
            f"REG_BINARY value must be bytes or a hex string, got {value!r}"
        )
    # REG_NONE / REG_LINK: pass through unchanged.
    return value


class RegistryBackend(ABC):
    """Interface every registry backend implements."""

    view: str

    @abstractmethod
    def read(self, hive: str, path: str, value_name: str) -> tuple[Any, str]:
        """Return ``(value, reg_type_name)`` or raise RegistryNotFoundError."""
        raise NotImplementedError

    @abstractmethod
    def write(
        self,
        hive: str,
        path: str,
        value_name: str,
        reg_type: str,
        value: Any,
        *,
        create_keys: bool = True,
    ) -> None:
        """Write a value; raise RegistryNotFoundError if the key is missing
        and ``create_keys`` is False."""
        raise NotImplementedError

    @abstractmethod
    def delete_value(self, hive: str, path: str, value_name: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def key_exists(self, hive: str, path: str) -> bool:
        raise NotImplementedError


class WinRegBackend(RegistryBackend):
    """The real backend, backed by ``winreg`` (Windows only)."""

    def __init__(self, view: str = "64") -> None:
        if view not in ("32", "64"):
            raise ValueError("registry view must be '32' or '64'")
        self.view = view
        try:
            import winreg  # noqa: PLC0415
        except ImportError as exc:
            raise RegistryUnavailableError(
                "the Windows Registry is only available on Windows"
            ) from exc
        # Typed as Any: the winreg names below exist only on Windows,
        # and the Linux typeshed stub does not declare them, so they
        # are read with getattr instead of attribute access.
        self._winreg: Any = winreg
        flag_name = "KEY_WOW64_64KEY" if view == "64" else "KEY_WOW64_32KEY"
        self._view_flag: Any = getattr(winreg, flag_name)
        self._hive_handles: dict[str, Any] = {
            name: getattr(winreg, name)
            for name in (
                "HKEY_LOCAL_MACHINE",
                "HKEY_CURRENT_USER",
                "HKEY_CLASSES_ROOT",
                "HKEY_USERS",
                "HKEY_CURRENT_CONFIG",
            )
        }

    def _handle(self, hive: str) -> int:
        return int(self._hive_handles[normalize_hive(hive)])

    @staticmethod
    def _wrap_os_error(exc: OSError, hive: str, path: str) -> RegistryError:
        if getattr(exc, "winerror", None) == 5:
            return RegistryPermissionError(
                f"permission denied for {hive}\\{path}; run as administrator"
            )
        return RegistryError(f"registry error for {hive}\\{path}: {exc}")

    def read(self, hive: str, path: str, value_name: str) -> tuple[Any, str]:
        winreg = self._winreg
        cleaned = normalize_path(path)
        try:
            with winreg.OpenKey(
                self._handle(hive), cleaned, 0, winreg.KEY_READ | self._view_flag
            ) as key:
                value, reg_code = winreg.QueryValueEx(key, value_name)
        except FileNotFoundError as exc:
            raise RegistryNotFoundError(
                f"{normalize_hive(hive)}\\{cleaned}\\{value_name} does not exist"
            ) from exc
        except PermissionError as exc:
            raise RegistryPermissionError(
                f"permission denied reading {normalize_hive(hive)}\\{cleaned}; "
                "run as administrator"
            ) from exc
        except OSError as exc:
            raise self._wrap_os_error(exc, hive, cleaned) from exc
        return value, REG_TYPE_CODES.get(reg_code, f"REG_UNKNOWN({reg_code})")

    def write(
        self,
        hive: str,
        path: str,
        value_name: str,
        reg_type: str,
        value: Any,
        *,
        create_keys: bool = True,
    ) -> None:
        winreg = self._winreg
        cleaned = normalize_path(path)
        reg_code = REG_TYPE_NAMES[reg_type.upper()]
        data = coerce_value(reg_type, value)
        try:
            if create_keys:
                key = winreg.CreateKeyEx(
                    self._handle(hive), cleaned, 0, winreg.KEY_WRITE | self._view_flag
                )
            else:
                key = winreg.OpenKey(
                    self._handle(hive),
                    cleaned,
                    0,
                    winreg.KEY_SET_VALUE | self._view_flag,
                )
            with key:
                winreg.SetValueEx(key, value_name, 0, reg_code, data)
        except FileNotFoundError as exc:
            raise RegistryNotFoundError(
                f"registry key {normalize_hive(hive)}\\{cleaned} does not exist"
            ) from exc
        except PermissionError as exc:
            raise RegistryPermissionError(
                f"permission denied writing {normalize_hive(hive)}\\{cleaned}; "
                "run as administrator"
            ) from exc
        except OSError as exc:
            raise self._wrap_os_error(exc, hive, cleaned) from exc

    def delete_value(self, hive: str, path: str, value_name: str) -> None:
        winreg = self._winreg
        cleaned = normalize_path(path)
        try:
            with winreg.OpenKey(
                self._handle(hive),
                cleaned,
                0,
                winreg.KEY_SET_VALUE | self._view_flag,
            ) as key:
                winreg.DeleteValue(key, value_name)
        except FileNotFoundError as exc:
            raise RegistryNotFoundError(
                f"{normalize_hive(hive)}\\{cleaned}\\{value_name} does not exist"
            ) from exc
        except PermissionError as exc:
            raise RegistryPermissionError(
                f"permission denied deleting {normalize_hive(hive)}\\{cleaned}; "
                "run as administrator"
            ) from exc
        except OSError as exc:
            raise self._wrap_os_error(exc, hive, cleaned) from exc

    def key_exists(self, hive: str, path: str) -> bool:
        winreg = self._winreg
        try:
            with winreg.OpenKey(
                self._handle(hive),
                normalize_path(path),
                0,
                winreg.KEY_READ | self._view_flag,
            ):
                return True
        except FileNotFoundError:
            return False
        except PermissionError as exc:
            # Denied access is not absence: callers must not conclude
            # a key is missing when they simply cannot read it.
            raise RegistryPermissionError(
                f"permission denied reading {normalize_hive(hive)}\\"
                f"{normalize_path(path)}; run as administrator"
            ) from exc
        except OSError as exc:
            raise self._wrap_os_error(exc, hive, normalize_path(path)) from exc


class FakeRegistryBackend(RegistryBackend):
    """In-memory registry for tests and dry runs.

    Keys track existence separately from values, so a write with
    ``create_keys=False`` to a missing key fails the way the real
    backend fails.
    """

    def __init__(self, view: str = "64") -> None:
        if view not in ("32", "64"):
            raise ValueError("registry view must be '32' or '64'")
        self.view = view
        self._values: dict[tuple[str, str, str], tuple[Any, str]] = {}
        self._keys: set[tuple[str, str]] = set()

    def seed(
        self, hive: str, path: str, value_name: str, reg_type: str, value: Any
    ) -> None:
        """Put a value in place, creating its key."""
        hive_n = normalize_hive(hive)
        path_n = normalize_path(path)
        self._keys.add((hive_n, path_n))
        self._values[(hive_n, path_n, value_name)] = (
            coerce_value(reg_type, value),
            reg_type.upper(),
        )

    def create_key(self, hive: str, path: str) -> None:
        self._keys.add((normalize_hive(hive), normalize_path(path)))

    def snapshot(self) -> dict[tuple[str, str, str], tuple[Any, str]]:
        return dict(self._values)

    def read(self, hive: str, path: str, value_name: str) -> tuple[Any, str]:
        key = (normalize_hive(hive), normalize_path(path), value_name)
        try:
            return self._values[key]
        except KeyError as exc:
            raise RegistryNotFoundError(
                f"{key[0]}\\{key[1]}\\{value_name} does not exist"
            ) from exc

    def write(
        self,
        hive: str,
        path: str,
        value_name: str,
        reg_type: str,
        value: Any,
        *,
        create_keys: bool = True,
    ) -> None:
        hive_n = normalize_hive(hive)
        path_n = normalize_path(path)
        if not create_keys and (hive_n, path_n) not in self._keys:
            raise RegistryNotFoundError(
                f"registry key {hive_n}\\{path_n} does not exist"
            )
        self._keys.add((hive_n, path_n))
        self._values[(hive_n, path_n, value_name)] = (
            coerce_value(reg_type, value),
            reg_type.upper(),
        )

    def delete_value(self, hive: str, path: str, value_name: str) -> None:
        key = (normalize_hive(hive), normalize_path(path), value_name)
        try:
            del self._values[key]
        except KeyError as exc:
            raise RegistryNotFoundError(
                f"{key[0]}\\{key[1]}\\{value_name} does not exist"
            ) from exc

    def key_exists(self, hive: str, path: str) -> bool:
        return (normalize_hive(hive), normalize_path(path)) in self._keys


def create_backend(view: str = "64") -> WinRegBackend:
    """Create the real backend, or raise RegistryUnavailableError."""
    return WinRegBackend(view=view)
