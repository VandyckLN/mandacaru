"""Configuracao do Mandacaru a partir de um arquivo TOML.

Chave desconhecida ou tipo errado e erro, nunca e ignorado: um erro de
digitacao nao pode desligar protecao em silencio.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from .events import Severity

DEFAULT_PATH = "/etc/mandacaru/config.toml"


class ConfigError(ValueError):
    """Arquivo de configuracao ausente, ilegivel ou invalido."""


@dataclass(frozen=True)
class Config:
    watch_paths: tuple[str, ...] = ()
    ebpf: bool = True
    min_severity: Severity = Severity.LOW
    json_path: str | None = None
    rule_dirs: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()


def _str_list(value, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{key}: esperava uma lista de textos")
    return tuple(value)


def _bool(value, key: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{key}: esperava true ou false")
    return value


def _str(value, key: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{key}: esperava um texto")
    return value


def _severity(value, key: str) -> Severity:
    name = _str(value, key).upper()
    if name not in Severity.__members__:
        raise ConfigError(f"{key}: valor invalido {value!r}; use um de {', '.join(Severity.__members__)}")
    return Severity[name]


# secao -> chave -> (campo do Config, conversor)
_SCHEMA = {
    "monitor": {"paths": ("watch_paths", _str_list), "ebpf": ("ebpf", _bool)},
    "alerts": {"min_severity": ("min_severity", _severity), "json": ("json_path", _str)},
    "rules": {"dirs": ("rule_dirs", _str_list)},
    "exclude": {"paths": ("exclude", _str_list)},
}


def load_config(path: str | os.PathLike | None = None) -> Config:
    """Le o config. Sem `path`, usa DEFAULT_PATH se existir, senao os padroes."""
    if path is None:
        if not Path(DEFAULT_PATH).is_file():
            return Config()
        path = DEFAULT_PATH
    try:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    except OSError as exc:
        raise ConfigError(f"{path}: nao foi possivel ler ({exc.strerror or exc})") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: TOML invalido: {exc}") from exc

    fields = {}
    try:
        for section, body in raw.items():
            if section not in _SCHEMA:
                raise ConfigError(f"secao desconhecida [{section}]; validas: {', '.join(_SCHEMA)}")
            if not isinstance(body, dict):
                raise ConfigError(f"{section}: esperava uma secao [{section}]")
            for key, value in body.items():
                if key not in _SCHEMA[section]:
                    raise ConfigError(
                        f"chave desconhecida {section}.{key}; validas: {', '.join(_SCHEMA[section])}")
                field, convert = _SCHEMA[section][key]
                fields[field] = convert(value, f"{section}.{key}")
    except ConfigError as exc:
        raise ConfigError(f"{path}: {exc}") from None
    return Config(**fields)
