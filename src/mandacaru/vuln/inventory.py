"""Inventario de pacotes instalados (Debian/Ubuntu) e correlacao com processos ativos."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

_SOURCE_RE = re.compile(r"^([^\s(]+)(?:\s+\(([^)]+)\))?")


@dataclass(frozen=True)
class InstalledPackage:
    binary_name: str
    source_name: str
    version: str
    ecosystem: str


def detect_ecosystem(os_release_path: Path = Path("/etc/os-release")) -> str:
    """Retorna o identificador de ecossistema no formato esperado pelo OSV.dev (ex.: Debian:12, Ubuntu:24.04)."""
    if not os_release_path.exists():
        return "Debian"

    data: dict[str, str] = {}
    for line in os_release_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip().strip('"')

    distro_id = data.get("ID", "").lower()
    version_id = data.get("VERSION_ID", "").strip()

    if distro_id == "debian":
        return f"Debian:{version_id}" if version_id else "Debian"
    if distro_id in {"ubuntu", "pop", "linuxmint", "elementary"}:
        return f"Ubuntu:{version_id}" if version_id else "Ubuntu"
    return "Debian"


def parse_dpkg_status(
    status_path: Path = Path("/var/lib/dpkg/status"),
    ecosystem: str | None = None,
) -> list[InstalledPackage]:
    """Extrai pacotes instalados de /var/lib/dpkg/status deduplicados por (source_name, version)."""
    eco = ecosystem or detect_ecosystem()
    raw = status_path.read_text(encoding="utf-8", errors="ignore")
    seen: set[tuple[str, str]] = set()
    packages: list[InstalledPackage] = []

    for stanza in raw.strip().split("\n\n"):
        fields: dict[str, str] = {}
        for line in stanza.splitlines():
            if line.startswith((" ", "\t")) or ":" not in line:
                continue
            key, val = line.split(":", 1)
            fields[key.strip()] = val.strip()

        if fields.get("Status") != "install ok installed":
            continue

        binary = fields.get("Package")
        version = fields.get("Version")
        if not binary or not version:
            continue

        source_raw = fields.get("Source", "")
        source_name = binary
        source_version = version
        if source_raw:
            match = _SOURCE_RE.match(source_raw)
            if match:
                source_name = match.group(1)
                if match.group(2):
                    source_version = match.group(2)

        dedup_key = (source_name, source_version)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        packages.append(
            InstalledPackage(
                binary_name=binary,
                source_name=source_name,
                version=source_version,
                ecosystem=eco,
            )
        )

    return packages


def _read_dpkg_file_index(dpkg_info_dir: Path = Path("/var/lib/dpkg/info")) -> dict[str, str]:
    """Mapeia caminhos absolutos de binarios/libs para o nome do pacote binario via arquivos .list do dpkg."""
    index: dict[str, str] = {}
    if not dpkg_info_dir.is_dir():
        return index
    for list_file in dpkg_info_dir.glob("*.list"):
        pkg_name = list_file.stem.split(":", 1)[0]
        try:
            content = list_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in content.splitlines():
            if line.startswith(("/usr/", "/bin/", "/sbin/", "/lib/")):
                index[line] = pkg_name
    return index


def find_running_packages(
    packages: list[InstalledPackage],
    proc_root: Path = Path("/proc"),
    dpkg_info_dir: Path = Path("/var/lib/dpkg/info"),
) -> set[str]:
    """Retorna os nomes de pacotes-fonte com executaveis ou bibliotecas mapeadas em processos ativos."""
    if not proc_root.is_dir():
        return set()

    bin_to_source = {p.binary_name: p.source_name for p in packages}
    file_index = _read_dpkg_file_index(dpkg_info_dir)
    if not file_index:
        return set()

    active_paths: set[str] = set()
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            exe = os.readlink(entry / "exe")
            active_paths.add(exe.removesuffix(" (deleted)"))
        except OSError:
            pass
        maps_file = entry / "maps"
        try:
            for line in maps_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split(None, 5)
                if len(parts) == 6 and parts[5].startswith("/"):
                    active_paths.add(parts[5].removesuffix(" (deleted)"))
        except OSError:
            pass

    running_sources: set[str] = set()
    for path in active_paths:
        bin_pkg = file_index.get(path)
        if bin_pkg and bin_pkg in bin_to_source:
            running_sources.add(bin_to_source[bin_pkg])
    return running_sources
