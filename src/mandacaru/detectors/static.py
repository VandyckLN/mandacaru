"""Analise estatica de arquivos: regras YARA + heuristicas de ofuscacao.

Malware gerado por LLM muda a cada geracao, entao hash/assinatura exata
envelhece rapido. As heuristicas aqui olham para *tecnicas* (ofuscar,
decodificar e executar) em vez de bytes especificos.
"""
from __future__ import annotations

import math
import os
import re
from collections import Counter
from importlib import resources
from pathlib import Path
from typing import Iterable, Iterator

import yara

from ..events import Alert, Severity

MAX_BYTES = 8 * 1024 * 1024          # nao le arquivos gigantes inteiros
SCRIPT_EXT = {".py", ".ps1", ".psm1", ".js", ".mjs", ".vbs", ".sh", ".bash", ".bat", ".cmd", ".php", ".rb", ".pl"}
_SEV = {s.name: s for s in Severity}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def load_rules(extra_dirs: Iterable[str | os.PathLike] = ()) -> yara.Rules:
    files: dict[str, str] = {}
    base = resources.files("mandacaru") / "rules" / "yara"
    for f in base.iterdir():
        if f.name.endswith(".yar"):
            files[f"base_{f.name}"] = str(f)
    for d in extra_dirs:
        for p in Path(d).glob("*.yar"):
            files[f"user_{p.name}"] = str(p)
    return yara.compile(filepaths=files)


# --- heuristicas de ofuscacao para scripts ----------------------------------
_B64_BLOB = re.compile(rb"[A-Za-z0-9+/]{200,}={0,2}")
_HEX_BLOB = re.compile(rb"(?:\\x[0-9a-fA-F]{2}){40,}")
_CHR_CHAIN = re.compile(rb"(?:chr\(\d+\)\s*\+\s*){15,}|(?:\[char\]\s*\d+\s*\+\s*){15,}", re.I)
_DECODE = re.compile(rb"(b64decode|atob\(|FromBase64String|decompress|fromhex|unescape\(|fromCharCode|\[char\])", re.I)
_DYN_EXEC = re.compile(rb"\b(exec|eval|iex|invoke-expression|Function\(|setTimeout\(\s*['\"])", re.I)


def script_heuristics(path: Path, data: bytes) -> list[Alert]:
    alerts: list[Alert] = []
    if path.suffix.lower() not in SCRIPT_EXT:
        return alerts
    reasons: list[str] = []
    score = 0
    encoded = 0
    if _B64_BLOB.search(data):
        reasons.append("blob base64 longo"); score += 2; encoded += 1
    if _HEX_BLOB.search(data):
        reasons.append("bytes em \\x hex"); score += 2; encoded += 1
    if _CHR_CHAIN.search(data):
        reasons.append("cadeia de chr()/[char]"); score += 2; encoded += 1
    lines = data.splitlines() or [b""]
    longest = max(len(l) for l in lines)
    if longest > 1500:
        reasons.append(f"linha com {longest} caracteres"); score += 1
    ent = shannon_entropy(data[:65536])
    if ent > 5.6:
        reasons.append(f"entropia {ent:.2f}"); score += 1
    if _DYN_EXEC.search(data):
        reasons.append("execucao dinamica de codigo"); score += 1
    if _DECODE.search(data):
        reasons.append("funcao de decodificacao"); score += 1
    # so alerta com conteudo codificado + decodificacao + execucao dinamica:
    # codigo minificado comum tem linhas longas e eval, mas nao os tres juntos
    if encoded and score >= 4 and _DECODE.search(data) and _DYN_EXEC.search(data):
        sev = Severity.HIGH if score >= 5 else Severity.MEDIUM
        if len(data) > 256 * 1024:
            # bundles grandes (webpack/vite) embutem base64 legitimo; rebaixa
            sev = Severity.LOW
            reasons.append("arquivo grande (provavel bundle): severidade rebaixada")
        alerts.append(Alert(
            rule="heur.obfuscated_script", severity=sev,
            summary=f"Script ofuscado que executa codigo dinamico: {path.name}",
            evidence={"path": str(path), "score": score, "reasons": reasons},
            mitre=["T1027", "T1059"],
        ))
    return alerts


class StaticScanner:
    def __init__(self, extra_rule_dirs: Iterable[str] = ()):
        self.rules = load_rules(extra_rule_dirs)

    def scan_bytes(self, path: Path, data: bytes) -> list[Alert]:
        alerts: list[Alert] = []
        for m in self.rules.match(data=data):
            meta = m.meta or {}
            alerts.append(Alert(
                rule=f"yara.{m.rule}",
                severity=_SEV.get(str(meta.get("severity", "MEDIUM")).upper(), Severity.MEDIUM),
                summary=f"{meta.get('description', m.rule)}: {path.name}",
                evidence={"path": str(path), "strings": sorted({s.identifier for s in m.strings})},
                mitre=[t for t in str(meta.get("mitre", "")).split(",") if t],
            ))
        alerts += script_heuristics(path, data)
        return alerts

    def scan_file(self, path: str | os.PathLike) -> list[Alert]:
        p = Path(path)
        try:
            if not p.is_file() or p.is_symlink():
                return []
            with p.open("rb") as fh:
                data = fh.read(MAX_BYTES)
        except (PermissionError, OSError):
            return []
        return self.scan_bytes(p, data)

    def scan_tree(self, root: str | os.PathLike) -> Iterator[Alert]:
        root = Path(root)
        if root.is_file():
            yield from self.scan_file(root)
            return
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__", ".venv"}]
            for fn in filenames:
                yield from self.scan_file(Path(dirpath) / fn)
