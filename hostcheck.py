#!/usr/bin/env python3
"""
hostcheck — verificações rápidas de conectividade de um host.

Para cada alvo executa, em paralelo:
  1. resolução DNS
  2. conexão TCP nas portas indicadas
  3. status HTTP/HTTPS (quando houver porta 80/443 aberta)
  4. validade do certificado TLS

Uso:
    python hostcheck.py github.com
    python hostcheck.py https://github.com --ports 443
    python hostcheck.py api.exemplo.com --ports 80,443,8080 --timeout 3
    python hostcheck.py github.com 1.1.1.1 --json

Sai com código 1 se qualquer verificação falhar — útil em CI e cron.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

DEFAULT_PORTS = (80, 443)
DEFAULT_TIMEOUT = 5.0

OK, WARN, FAIL = "OK", "WARN", "FAIL"

_ANSI = {OK: "\033[92m", WARN: "\033[93m", FAIL: "\033[91m"}
_RESET = "\033[0m"


@dataclass
class Check:
    """Resultado de uma única verificação."""

    name: str
    status: str
    detail: str
    ms: float = 0.0


@dataclass
class Report:
    """Resultado consolidado de um alvo."""

    target: str
    host: str
    checks: list[Check] = field(default_factory=list)

    @property
    def status(self) -> str:
        if any(c.status == FAIL for c in self.checks):
            return FAIL
        if any(c.status == WARN for c in self.checks):
            return WARN
        return OK


# ─────────────────────────── verificações ───────────────────────────


def _now() -> float:
    return time.perf_counter()


def check_dns(host: str, timeout: float) -> Check:
    start = _now()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(host, None)
        elapsed = (_now() - start) * 1000
        addrs = sorted({i[4][0] for i in infos})
        return Check("dns", OK, ", ".join(addrs[:3]), round(elapsed, 1))
    except OSError as exc:
        return Check("dns", FAIL, f"{type(exc).__name__}: {exc}", round((_now() - start) * 1000, 1))


def check_tcp(host: str, port: int, timeout: float) -> Check:
    start = _now()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return Check(f"tcp/{port}", OK, "conectado", round((_now() - start) * 1000, 1))
    except OSError as exc:
        return Check(f"tcp/{port}", FAIL, str(exc) or type(exc).__name__, round((_now() - start) * 1000, 1))


def check_http(url: str, timeout: float) -> Check:
    start = _now()
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "hostcheck/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.status
            status = OK if code < 400 else WARN
            return Check("http", status, f"HTTP {code}", round((_now() - start) * 1000, 1))
    except urllib.error.HTTPError as exc:
        status = WARN if exc.code < 500 else FAIL
        return Check("http", status, f"HTTP {exc.code}", round((_now() - start) * 1000, 1))
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return Check("http", FAIL, f"{reason}", round((_now() - start) * 1000, 1))


def check_tls(host: str, port: int, timeout: float) -> Check:
    start = _now()
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
    except (ssl.SSLError, OSError) as exc:
        return Check("tls", FAIL, f"{type(exc).__name__}: {exc}", round((_now() - start) * 1000, 1))

    not_after = cert.get("notAfter")
    if not not_after:
        return Check("tls", WARN, "sem notAfter no certificado", 0.0)

    remaining = ssl.cert_time_to_seconds(not_after) - time.time()
    days = int(remaining // 86400)
    elapsed = round((_now() - start) * 1000, 1)

    if days < 0:
        return Check("tls", FAIL, f"expirado há {-days} dia(s)", elapsed)
    if days < 14:
        return Check("tls", WARN, f"expira em {days} dia(s)", elapsed)
    return Check("tls", OK, f"válido por mais {days} dia(s)", elapsed)


# ─────────────────────────── orquestração ───────────────────────────


def normalize(target: str, ports: tuple[int, ...]) -> tuple[str, str, tuple[int, ...]]:
    """Devolve (alvo_original, host, portas) a partir de uma URL ou host puro."""
    raw = target.strip()
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname
    if not host:
        raise ValueError(f"alvo inválido: {target!r}")

    scheme = parsed.scheme if "://" in raw else ""
    if parsed.port:
        ports = (parsed.port,)
    elif scheme == "http" and 80 not in ports:
        ports = ports + (80,)
    return raw, host, ports


def probe(target: str, ports: tuple[int, ...], timeout: float) -> Report:
    raw, host, ports = normalize(target, ports)
    report = Report(target=raw, host=host)

    with ThreadPoolExecutor(max_workers=max(8, len(ports) + 3)) as pool:
        jobs = {pool.submit(check_dns, host, timeout): None}

        def add(check_future):
            jobs[check_future] = None

        for port in ports:
            add(pool.submit(check_tcp, host, port, timeout))

        # HTTP só faz sentido se alguma porta web estiver aberta
        results: dict[str, Check] = {}

        for future in as_completed(list(jobs)):
            results[future.result().name] = future.result()

        has_http = any(results.get(f"tcp/{p}") and results[f"tcp/{p}"].status == OK
                       for p in ports)
        if has_http:
            scheme = "https" if 443 in ports else "http"
            with ThreadPoolExecutor(max_workers=2) as inner:
                http_f = inner.submit(check_http, f"{scheme}://{host}", timeout)
                tls_f = inner.submit(check_tls, host, 443, timeout) if 443 in ports else None
                results["http"] = http_f.result()
                if tls_f:
                    results["tls"] = tls_f.result()

    order = {"dns": 0}
    order.update({f"tcp/{p}": 1 + i for i, p in enumerate(ports)})
    order.update({"http": 90, "tls": 91})

    report.checks = sorted(results.values(), key=lambda c: order.get(c.name, 50))
    return report


# ─────────────────────────── saída ───────────────────────────


def render_text(reports: list[Report]) -> str:
    lines: list[str] = []
    for r in reports:
        color = _ANSI[r.status]
        lines.append(f"{color}[{r.status}]{_RESET} {r.target}")
        for c in r.checks:
            ccolor = _ANSI[c.status]
            timing = f"{c.ms:>7.1f} ms" if c.ms else " " * 9
            lines.append(f"    {ccolor}{c.status:<4}{_RESET} {c.name:<10} {timing}  {c.detail}")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_json(reports: list[Report]) -> str:
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "results": [
            {**asdict(r), "status": r.status}
            for r in reports
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_markdown(reports: list[Report]) -> str:
    lines = ["| Alvo | Resultado | Verificações |", "|---|---|---|"]
    for r in reports:
        detail = " · ".join(f"{c.name}: {c.status}" for c in r.checks)
        lines.append(f"| `{r.target}` | **{r.status}** | {detail} |")
    return "\n".join(lines)


# ─────────────────────────── CLI ───────────────────────────


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="hostcheck",
        description="Verifica DNS, portas, HTTP e certificado TLS de um ou mais alvos.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("targets", nargs="+", metavar="ALVO", help="host ou URL (ex.: github.com)")
    parser.add_argument("--ports", default=",".join(str(p) for p in DEFAULT_PORTS),
                        help="lista de portas TCP separadas por vírgula")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="timeout por verificação, em segundos")
    parser.add_argument("--json", action="store_true", help="saída JSON")
    parser.add_argument("--markdown", action="store_true", help="saída em tabela Markdown")
    parser.add_argument("--no-color", action="store_true", help="desativa cores ANSI")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        ports = tuple(int(p) for p in str(args.ports).split(",") if p.strip())
    except ValueError:
        print("erro: --ports precisa ser uma lista de números (ex.: 80,443)", file=sys.stderr)
        return 2

    if not ports:
        print("erro: nenhuma porta válida em --ports", file=sys.stderr)
        return 2

    reports: list[Report] = []
    for target in args.targets:
        try:
            reports.append(probe(target, ports, args.timeout))
        except ValueError as exc:
            print(f"erro: {exc}", file=sys.stderr)
            return 2

    if args.json:
        print(render_json(reports))
    elif args.markdown:
        print(render_markdown(reports))
    else:
        text = render_text(reports)
        if args.no_color:
            for code in _ANSI.values():
                text = text.replace(code, "")
        print(text)

    return 1 if any(r.status == FAIL for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
