"""`mandacaru quarentena ...`: listar, analisar, manter, confiar, apagar, desconfiar e limpar.

Roda como root via os auxiliares do pkexec (ou sudo); o popup le a saida e os codigos de saida:
0 ok, 1 uso/config, 3 id inexistente ou ja resolvido, 4 quarentena adulterada.
"""
from __future__ import annotations

import http.client
import json
import math
import os
import re
import sys
import time
from pathlib import Path

from . import analysis
from .analysis import MAX_UPLOAD, SourceResult
from .decisions import DEFAULT_LOG, DecisionLog, actor_from_env
from .events import safe_text
from .quarantine import (
    DEFAULT_DIR,
    DEFAULT_TRUST,
    CaseNotFound,
    LogNotRecorded,
    Quarantine,
    Tampered,
    TrustList,
    UnsafePath,
    validate_id,
)

NEEDS_ROOT = "este comando precisa de root (use sudo ou o botao do popup)"
UPLOAD_PROMPT = "O arquivo ficara acessivel a pesquisadores e empresas parceiras do VirusTotal. Enviar? [s/N] "
_SHA256 = re.compile(r"[0-9a-f]{64}")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class _Fail(Exception):
    """Erro de uso: saida 1 com a mensagem."""


def add_parser(sub) -> None:
    p = sub.add_parser("quarentena", help="decide sobre arquivos isolados")
    qs = p.add_subparsers(dest="qcmd", required=True)
    qs.add_parser("listar", help="lista os casos em quarentena")
    a = qs.add_parser("analisar", help="consulta o hash em servicos de reputacao")
    a.add_argument("id")
    a.add_argument("--json", dest="as_json", action="store_true", help="uma linha JSON em stdout")
    a.add_argument("--enviar", action="store_true", help="envia o arquivo ao VirusTotal (pede confirmacao)")
    for name, help_ in (("manter", "mantem isolado ate expirar"), ("confiar", "restaura e passa a confiar"),
                        ("apagar", "apaga agora")):
        qs.add_parser(name, help=help_).add_argument("id")
    qs.add_parser("desconfiar", help="tira um hash da lista de confianca").add_argument("sha256")
    qs.add_parser("limpar", help="apaga os casos vencidos")
    p.set_defaults(fn=cmd_quarentena)


def _production_quarantine(cfg) -> Quarantine:
    mb = 1024 * 1024
    return Quarantine(DEFAULT_DIR, DecisionLog(DEFAULT_LOG), TrustList(DEFAULT_TRUST), cfg.retention_days,
                      cfg.max_file_mb * mb, cfg.max_total_mb * mb, strict_log=True)


def _check_log(q: Quarantine) -> None:
    """Toda decisao vai para o log: se ele nao abre para acrescentar, nada e feito."""
    if q.log is None:
        return
    try:
        fd = os.open(q.log.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
    except OSError as e:
        raise _Fail(f"log de decisoes indisponivel: {e.strerror or e}") from None
    os.close(fd)


def _clean(s: str) -> str:
    """Texto de uma celula: sem surrogates e sem controle (um nome com \\n nao forja linhas)."""
    return _CTRL.sub(lambda m: f"\\x{ord(m.group()):02x}", safe_text(s))


def _os_message(e: OSError) -> str:
    if isinstance(e, PermissionError):
        return f"sem permissao: {e.filename}" if e.filename else "sem permissao"
    if isinstance(e, FileExistsError):
        return "o caminho original e o nome de restauracao ja existem"
    msg = e.strerror or str(e)
    return f"{msg}: {e.filename}" if e.filename else msg


def cmd_quarentena(args, *, quarantine: Quarantine | None = None, euid: int | None = None, env=os.environ,
                   analyzer=analysis.analyze, stdin_isatty=sys.stdin.isatty, input_fn=input,
                   uploader=analysis.upload_virustotal) -> int:
    if euid is None:
        euid = os.geteuid()
    try:
        if args.qcmd != "listar" and euid != 0:
            raise _Fail(NEEDS_ROOT)
        from .cli import effective_config  # import tardio: cli importa este modulo
        cfg = effective_config(args)
        q = quarantine if quarantine is not None else _production_quarantine(cfg)
        if args.qcmd != "listar":
            _check_log(q)
        ctx = _Ctx(args, cfg, q, env, analyzer, stdin_isatty, input_fn, uploader)
        return getattr(ctx, args.qcmd)()
    except LogNotRecorded as e:
        print(f"mandacaru: erro: decisao aplicada, mas nao registrada no log: {e}", file=sys.stderr)
        return 1
    except CaseNotFound as e:
        print(f"mandacaru: erro: caso nao encontrado ou ja resolvido: {e}", file=sys.stderr)
        return 3
    except Tampered as e:
        print(f"mandacaru: erro: quarentena adulterada: {e}", file=sys.stderr)
        return 4
    except (UnsafePath, OSError) as e:
        print(f"mandacaru: erro: {_os_message(e)}", file=sys.stderr)
        return 1
    except (_Fail, ValueError) as e:  # ConfigError e ValueError
        print(f"mandacaru: erro: {e}", file=sys.stderr)
        return 1


class _Ctx:
    def __init__(self, args, cfg, q, env, analyzer, stdin_isatty, input_fn, uploader):
        self.args, self.cfg, self.q = args, cfg, q
        self.env, self.analyzer, self.isatty, self.input, self.uploader = (
            env, analyzer, stdin_isatty, input_fn, uploader)

    def _log(self, action: str, **kw) -> None:
        # mesmo caminho de manter/confiar/apagar; aqui sempre estrito, mesmo com Quarantine injetada
        self.q._record(action, strict=True, **kw)

    # --- listar (grupo mandacaru, sem root) ---
    def listar(self) -> int:
        os.listdir(self.q.root)  # sem acesso ao diretorio e erro, nao "nenhum caso"
        cases = self.q.list()
        if not cases:
            print("Nenhum caso em quarentena.")
            return 0
        now = self.q.now()
        print("ID\tDATA\tARQUIVO\tREGRA\tEXPIRA EM\tANALISE")
        for c in cases:
            days = max(0, math.ceil((c.expires_at - now) / 86400))
            verdict = (c.analysis or {}).get("verdict") or "-"
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(c.quarantined_at))
            print("\t".join([c.id, when, _clean(c.original_path), _clean(c.rule), f"{days} dia(s)",
                             _clean(str(verdict))]))
        return 0

    # --- analisar ---
    def analisar(self) -> int:
        args, cfg, q = self.args, self.cfg, self.q
        validate_id(args.id)
        if args.enviar:
            if not cfg.virustotal_key:
                raise _Fail("--enviar exige analysis.virustotal_key no config (chave do VirusTotal)")
            if not self.isatty():
                raise _Fail("--enviar exige um terminal (TTY) para confirmar o envio")
        by, uid = actor_from_env(self.env)
        case = q.load(args.id)
        result = self.analyzer(case.id, case.sha256, cfg)
        active = [s for s in result.sources.values() if s.status != "desligada"]
        if active and all(s.status == "erro" for s in active):
            self._local_scan(case, result)
        detail = result.to_dict()
        q.set_analysis(case.id, detail)
        failure = None
        try:
            self._print(case.id, detail)
            if args.enviar:
                if result.verdict != "desconhecido":
                    failure = f"--enviar so vale para hash desconhecido (veredito: {result.verdict})"
                elif (answer := self._confirm()) is None:
                    failure = "envio nao confirmado (entrada encerrada ou interrompida)"
                elif answer.strip() in ("s", "S"):
                    data = q.read_original(case.id, MAX_UPLOAD)
                    try:
                        vt_id = self.uploader(data, os.path.basename(case.original_path), cfg.virustotal_key)
                    except (RuntimeError, OSError, http.client.HTTPException) as e:
                        failure = f"envio ao VirusTotal falhou: {e}"
                    else:
                        detail = {**detail, "enviado": True, "virustotal_analise": vt_id}
                        print(f"Enviado ao VirusTotal (analise {vt_id})", file=sys.stderr if args.as_json
                              else sys.stdout)
                else:
                    print("Envio cancelado.", file=sys.stderr if args.as_json else sys.stdout)
        finally:
            self._log("analisar", case_id=case.id, sha256=case.sha256, path=case.original_path, by=by, uid=uid,
                      detail=detail)
        if failure:
            raise _Fail(failure)
        return 0

    def _confirm(self) -> str | None:
        try:
            return self.input(UPLOAD_PROMPT)
        except (EOFError, KeyboardInterrupt):
            return None

    def _local_scan(self, case, result) -> None:
        """Nenhuma fonte respondeu: varre de novo com as regras YARA atuais (o veredito nao muda)."""
        from .detectors.static import StaticScanner
        try:
            data = self.q.read_original(case.id, self.q.max_file_bytes)
            alerts = StaticScanner(self.cfg.rule_dirs, ()).scan_bytes(Path(case.original_path), data)
        except Tampered:
            raise  # quarentena adulterada continua saindo com 4
        except Exception as e:  # noqa: BLE001 - varredura opcional nao derruba a analise de rede
            result.sources["yara_local"] = SourceResult("erro", _clean(str(e) or type(e).__name__)[:200])
            result.summary += "; YARA local: erro"
            return
        rules = ", ".join(dict.fromkeys(a.rule for a in alerts))
        if rules:
            result.sources["yara_local"] = SourceResult("achou", rules)
            result.summary += f"; YARA local: {rules}"
        else:
            result.sources["yara_local"] = SourceResult("nao_achou")
            result.summary += "; YARA local: nada encontrado"

    def _print(self, case_id: str, d: dict) -> None:
        if self.args.as_json:
            print(json.dumps(d, ensure_ascii=False))
            return
        print(_clean(d["summary"]))
        for name, s in d["sources"].items():
            print(f"  {name}: {s['status']}" + (f" ({_clean(s['detail'])})" if s["detail"] else ""))
        if self.isatty():
            print(f"Confiar: sudo mandacaru quarentena confiar {case_id} | "
                  f"Manter: sudo mandacaru quarentena manter {case_id}")

    # --- decisoes ---
    def manter(self) -> int:
        case = self.q.keep(self.args.id, *actor_from_env(self.env))
        until = time.strftime("%Y-%m-%d", time.localtime(case.expires_at))
        print(f"Caso {case.id} mantido em quarentena ate {until}")
        return 0

    def confiar(self) -> int:
        case = self.q.load(self.args.id)
        dest = self.q.restore(case.id, *actor_from_env(self.env))
        if dest != case.original_path:
            print(f"Restaurado como {_clean(dest)} (o caminho original ja existia)")
        else:
            print(f"Restaurado em {_clean(dest)}")
        return 0

    def apagar(self) -> int:
        validate_id(self.args.id)
        self.q.delete(self.args.id, *actor_from_env(self.env))
        print(f"Caso {self.args.id} apagado")
        return 0

    def desconfiar(self) -> int:
        sha = self.args.sha256
        if not _SHA256.fullmatch(sha):
            raise CaseNotFound(f"sha256 invalido: {sha!r}")
        if self.q.trust is None or not self.q.trust.remove(sha):
            raise CaseNotFound(f"hash fora da lista de confianca: {sha}")
        by, uid = actor_from_env(self.env)
        self._log("desconfiar", sha256=sha, by=by, uid=uid)
        print(f"Hash removido da lista de confianca: {sha}")
        return 0

    def limpar(self) -> int:
        print(f"{self.q.purge_expired()} caso(s) expirado(s) apagado(s)")
        return 0
