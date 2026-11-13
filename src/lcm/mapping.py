"""Canonical package identifiers and cross-family name resolution.

A profile never stores distro package names.  It stores canonical ids; this
module turns those into a name for the target family, or a Flatpak fallback,
or an honest "unknown".
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

import yaml

from lcm.util import LcmError

DATA_PATH = Path(__file__).resolve().parent / "data" / "mappings.yaml"

NON_PACKAGE_KEYS = {"flatpak", "note"}


@dataclass(frozen=True)
class Resolution:
    canonical: str
    family: str
    distro: str | None
    native: str | None
    flatpak: str | None
    confidence: str  # exact | family | flatpak | same-family | unknown
    note: str = ""
    source_name: str | None = None

    @property
    def installable(self) -> bool:
        return bool(self.native or self.flatpak)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


class Database:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else DATA_PATH
        try:
            raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        except OSError as exc:
            raise LcmError(f"cannot read mapping database: {self.path}") from exc
        except yaml.YAMLError as exc:
            raise LcmError(f"invalid mapping database: {self.path}: {exc}") from exc

        self.version = int(raw.get("version", 0))
        self.packages: dict[str, dict] = raw.get("packages") or {}
        self.updated = str(raw.get("updated", ""))

        self._reverse: dict[tuple[str, str], str] = {}
        for canonical, entry in self.packages.items():
            if not isinstance(entry, dict):
                continue
            for key, value in entry.items():
                if key in NON_PACKAGE_KEYS or not isinstance(value, str):
                    continue
                self._reverse.setdefault((key, value), canonical)

    # -- lookup -----------------------------------------------------------

    def canonical_for(self, family: str, native: str) -> str | None:
        return self._reverse.get((family, native))

    def resolve(
        self, canonical: str, family: str, distro: str | None = None
    ) -> Resolution:
        entry = self.packages.get(canonical)
        if not isinstance(entry, dict):
            return Resolution(canonical, family, distro, None, None, "unknown")

        note_value = entry.get("note", "")
        if isinstance(note_value, dict):
            note = str(note_value.get(distro or "") or note_value.get(family) or "")
        else:
            note = str(note_value)

        if distro and isinstance(entry.get(distro), str):
            return Resolution(
                canonical, family, distro, entry[distro], entry.get("flatpak"),
                "exact", note,
            )
        if isinstance(entry.get(family), str):
            return Resolution(
                canonical, family, distro, entry[family], entry.get("flatpak"),
                "family", note,
            )
        if isinstance(entry.get("flatpak"), str):
            return Resolution(
                canonical, family, distro, None, entry["flatpak"], "flatpak", note
            )
        return Resolution(canonical, family, distro, None, None, "unknown", note)

    def resolve_raw(
        self,
        name: str,
        source_family: str,
        target_family: str,
        *,
        source_distro: str | None = None,
        target_distro: str | None = None,
    ) -> Resolution:
        """Resolve a package name captured from the source system."""
        canonical = None
        if source_distro:
            canonical = self.canonical_for(source_distro, name)
        if canonical is None:
            canonical = self.canonical_for(source_family, name)

        if canonical is not None:
            return replace(
                self.resolve(canonical, target_family, target_distro),
                source_name=name,
            )
        if source_family == target_family:
            return Resolution(
                name, target_family, target_distro, name, None, "same-family",
                source_name=name,
            )
        return Resolution(
            name, target_family, target_distro, None, None, "unknown",
            source_name=name,
        )

    # -- introspection ----------------------------------------------------

    def canonical_ids(self) -> list[str]:
        return sorted(self.packages)

    def get(self, canonical: str) -> dict:
        entry = self.packages.get(canonical)
        return entry if isinstance(entry, dict) else {}


@dataclass
class MappingStats:
    total: int = 0
    native: int = 0
    flatpak: int = 0
    unknown: list[str] = None  # type: ignore[assignment]
    unknown_raw: list[str] = None  # type: ignore[assignment]
    exact: int = 0
    family: int = 0
    same_family: int = 0
    by_canonical: dict[str, Resolution] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.unknown is None:
            self.unknown = []
        if self.unknown_raw is None:
            self.unknown_raw = []
        if self.by_canonical is None:
            self.by_canonical = {}

    @property
    def mapped(self) -> int:
        return self.native + self.flatpak

    @property
    def percent(self) -> float:
        return (self.mapped / self.total * 100.0) if self.total else 0.0

    def add(self, resolution: Resolution) -> None:
        self.total += 1
        self.by_canonical[resolution.canonical] = resolution
        if resolution.native:
            self.native += 1
            if resolution.confidence == "exact":
                self.exact += 1
            elif resolution.confidence == "family":
                self.family += 1
            elif resolution.confidence == "same-family":
                self.same_family += 1
        elif resolution.flatpak:
            self.flatpak += 1
        else:
            self.unknown.append(resolution.canonical)
            if resolution.source_name:
                self.unknown_raw.append(resolution.source_name)

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "native": self.native,
            "flatpak": self.flatpak,
            "mapped": self.mapped,
            "percent": round(self.percent, 1),
            "unknown": sorted(set(self.unknown)),
            "unknown_raw": sorted(set(self.unknown_raw)),
            "exact": self.exact,
            "family": self.family,
        }
