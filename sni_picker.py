#!/usr/bin/env python3
"""Подбор рабочего SNI для своего TLS/VLESS-инбаунда.

Алгоритм и формат вывода взяты из cli/runners.py::run_whitelist_sni_test
(Тест 4 — "Поиск белых SNI для ASN"), но УБРАНО условие "перебираем SNI
только если AS заблокирована" (там: `if "DETECTED" not in row["status"]: continue`
и ранний выход "Ни одна AS не заблокирована — перебор SNI не нужен").
Здесь подбор идёт ВСЕГДА — скрипт ровно для подбора и нужен.

Что ещё отличается от теста 4:
  * цель — ваш сервер с инбаундом (IP:порт), а не список ASN;
  * фаза 1 только ЗАМЕРЯЕТ текущий SNI инбаунда (информация + RTT-хинт
    для ускорения проб), её результат ни на что не влияет;
  * проба по умолчанию имитирует VLESS-клиента: TLS handshake с нужным SNI
    плюс молчаливое удержание соединения (--probe tls);
  * сертификат инбаунда используется как эталон: если по какому-то SNI пришёл
    ДРУГОЙ серт — это уже не ваш сервер (заглушка/MITM/перехват), SNI отбрасывается;
  * найденные SNI перепроверяются (--verify) и пишутся в JSON/TXT.

Запускать из корня репозитория (нужны utils/, cli/, whitelist_sni.txt):

    python3 sni_picker.py --ip 1.2.3.4 -c current.example.com
    python3 sni_picker.py --ip 1.2.3.4 --port 8443 --all --verify 3
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from cli.console import console, install_crlf_stdout
from utils import config
from utils.error_classifier import classify_connect_error, classify_read_error
from utils.network import create_insecure_dpi_ssl_context

try:  # необязательно: помогает найти whitelist_sni.txt рядом с репозиторием/exe
    from utils.files import get_resource_path
except Exception:  # pragma: no cover
    def get_resource_path(relative_path: str) -> str:
        return relative_path

logger = logging.getLogger(__name__)

_DEFAULT_SNI_BATCH_SIZE = 5
_DEFAULT_SNI_TOP_N = 3
_TAG_RE = re.compile(r"\[.*?\]")


def _plain(text: str) -> str:
    """Снимает rich-разметку (для JSON/TXT-отчётов)."""
    return _TAG_RE.sub("", str(text or "")).strip()


async def _run_with_progress(tasks: list, description: str) -> list:
    """Как в cli/runners.py: одна перезаписываемая строка прогресса."""
    results = []
    total = len(tasks)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  transient=True) as progress:
        task_id = progress.add_task(description, total=total)
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            done = len(results)
            progress.update(task_id, completed=done,
                            description=f"{description} ({done}/{total})...")
    return results


# ── Пробы ─────────────────────────────────────────────────────


def _empty_result(sni: str, status: str, detail: str) -> dict:
    return {"sni": sni, "status": status, "detail": detail, "rtt": None,
            "fp": None, "tls": None, "alpn": None, "sent_kb": 0}


async def probe_sni_tls(
    ip: str,
    port: int,
    sni: str,
    hold: float = 3.0,
    kb: int = 0,
    tls_version: Optional[str] = None,
    tcp_ok: bool = True,
) -> dict:
    """Главная проба: ведёт себя как VLESS-клиент.

    TLS handshake с заданным SNI → (опционально) льём kb килобайт → молча держим
    соединение hold секунд. Проверяется именно то, что важно для инбаунда:
    доживает ли соединение с этим SNI до работы, а не "открыт ли порт".

    tcp_ok: TCP до цели уже проверен (фаза 0) — тогда таймаут здесь относится
    к handshake (SNI-блокировка), а не к SYN.
    """
    ctx = create_insecure_dpi_ssl_context(tls_version)
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass

    stage = "tls_handshake" if tcp_ok else "tcp_connect"
    chunk_size = getattr(config, "FAT_CHUNK_SIZE", 4000)
    chunk_delay = getattr(config, "FAT_CHUNK_DELAY", 0.05)
    min_detect_kb = getattr(config, "TCP_BLOCK_MIN_KB", 12)

    writer = None
    sent = 0
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=(sni or None)),
            timeout=config.FAT_CONNECT_TIMEOUT,
        )
    except Exception as e:
        logger.debug("TLS probe %s:%s sni=%r failed: %s", ip, port, sni, e, exc_info=True)
        label, detail, _ = classify_connect_error(e, 0, stage=stage)
        return _empty_result(sni, label, detail)

    rtt = time.monotonic() - start
    ssl_obj = writer.get_extra_info("ssl_object")
    fp = tls_ver = alpn = None
    if ssl_obj is not None:
        try:
            der = ssl_obj.getpeercert(binary_form=True)
            if der:
                fp = hashlib.sha256(der).hexdigest()[:16]
        except Exception:
            pass
        try:
            tls_ver = ssl_obj.version()
            alpn = ssl_obj.selected_alpn_protocol()
        except Exception:
            pass

    def _done(status: str, detail: str) -> dict:
        return {"sni": sni, "status": status, "detail": detail, "rtt": rtt,
                "fp": fp, "tls": tls_ver, "alpn": alpn, "sent_kb": sent // 1024}

    try:
        # Фаза объёма (--probe fat): часть DPI резалка срабатывает не на handshake,
        # а после 12-36 КБ переданных данных (логика core/tcp16_scanner.py).
        if kb > 0:
            target_bytes = kb * 1024
            while sent < target_bytes:
                writer.write(os.urandom(min(chunk_size, target_bytes - sent)))
                await writer.drain()
                sent += min(chunk_size, target_bytes - sent)
                try:
                    peek = await asyncio.wait_for(reader.read(4096), timeout=chunk_delay)
                    if peek == b"":
                        raise ConnectionResetError("peer closed connection (EOF)")
                except asyncio.TimeoutError:
                    pass  # тишина — это нормально

        # Фаза удержания: молчим и смотрим, не рвёт ли соединение кто-то со стороны.
        if hold > 0:
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=hold)
                if data == b"":
                    raise ConnectionResetError("peer closed connection (EOF)")
            except asyncio.TimeoutError:
                pass  # сервер молчит и соединение живо — именно так ведёт себя VLESS

        return _done("[green]OK[/green]", "")

    except Exception as e:
        logger.debug("TLS probe %s:%s sni=%r broke after %dB: %s", ip, port, sni, sent, e,
                     exc_info=True)
        label, detail, _ = classify_read_error(e, sent, stage="tls_connected")
        sent_kb = sent // 1024
        if sent_kb >= min_detect_kb:
            return _done("[bold red]DETECTED[/bold red]", f"{detail} at {sent_kb}KB")
        return _done(label, detail)

    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


async def probe_sni_http(ip: str, port: int, sni: str, semaphore: asyncio.Semaphore,
                        hint_rtt: Optional[float] = None) -> dict:
    """Альтернативная проба — родная из репозитория (тесты 3/4, HTTP-keepalive)."""
    from core.tcp16_scanner import check_tcp_16_20  # лениво: тянет httpx

    _alive, status, detail, rtt = await check_tcp_16_20(ip, port, sni, semaphore,
                                                       hint_rtt=hint_rtt)
    return {"sni": sni, "status": status, "detail": detail, "rtt": rtt,
            "fp": None, "tls": None, "alpn": None, "sent_kb": 0}


async def check_tcp_reachable(ip: str, port: int, timeout: float) -> Tuple[bool, str]:
    """Фаза 0: жив ли сам TCP-порт (без TLS). Отличает SYN DROP от TLS DROP."""
    writer = None
    try:
        _r, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        return True, ""
    except Exception as e:
        label, detail, _ = classify_connect_error(e, 0, stage="tcp_connect")
        return False, f"{_plain(label)} ({detail})" if detail else _plain(label)
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


# ── Подбор SNI для одной цели ────────────────────────────────────


class SniPicker:
    def __init__(self, args, sni_list: List[str], sni_index: dict):
        self.args = args
        self.sni_list = sni_list
        self.sni_index = sni_index
        self.semaphore = asyncio.Semaphore(args.concurrency)
        self.print_lock = asyncio.Lock()
        self.tls_version = None if args.tls == "auto" else args.tls

    async def _probe(self, ip: str, port: int, sni: str, hint_rtt: Optional[float] = None,
                     tcp_ok: bool = True) -> dict:
        if self.args.probe == "http":
            return await probe_sni_http(ip, port, sni, self.semaphore, hint_rtt=hint_rtt)
        async with self.semaphore:
            return await probe_sni_tls(
                ip, port, sni,
                hold=self.args.hold,
                kb=self.args.kb,
                tls_version=self.tls_version,
                tcp_ok=tcp_ok,
            )

    @staticmethod
    def _is_ok(r: dict) -> bool:
        return "OK" in r["status"]

    @staticmethod
    def _is_connect_level(r: dict) -> bool:
        """Ошибка уровня соединения (эвристика теста 4: нет OK/DETECTED и нет 'at ')."""
        return ("OK" not in r["status"]
                and "DETECTED" not in r["status"]
                and "at " not in (r["detail"] or ""))

    async def pick_for_target(self, target: dict) -> dict:
        """ВСЕГДА подбирает SNI для цели: замер текущего → перебор → верификация."""
        ip = target["ip"]
        port = int(target.get("port", 443))
        label = target.get("label") or ip
        current_sni = target.get("sni") or ""
        args = self.args

        # ── Фаза 0: TCP ──
        tcp_ok, tcp_detail = await check_tcp_reachable(ip, port, config.FAT_CONNECT_TIMEOUT)
        if not tcp_ok:
            console.print(
                f"  [cyan]{label}:{port}[/cyan]  [bold red]× порт недоступен[/bold red] "
                f"[dim]({tcp_detail})[/dim]"
            )
            return {
                "target": ip, "port": port, "label": label,
                "tcp": False, "tcp_detail": tcp_detail,
                "current_sni": current_sni, "current": None,
                "reference_cert_fp": None, "empty_sni": None,
                "checked": 0, "banned": False, "ban_detail": "",
                "picks": [], "rejected_cert_mismatch": [],
            }

        # ── Фаза 1/2: текущий SNI инбаунда — ТОЛЬКО информация, НЕ условие ──
        current_res = None
        if current_sni:
            runs = await _run_with_progress(
                [self._probe(ip, port, current_sni, tcp_ok=True)
                 for _ in range(max(1, args.verify))],
                f"Фаза 1/2: текущий SNI {current_sni}",
            )
            oks = [r for r in runs if self._is_ok(r)]
            rtts = [r["rtt"] for r in runs if r.get("rtt")]
            first_bad = next((r for r in runs if not self._is_ok(r)), None)
            current_res = {
                "sni": current_sni,
                "ok": len(oks),
                "runs": len(runs),
                "status": (oks[0]["status"] if oks and len(oks) == len(runs)
                           else (first_bad or runs[0])["status"]),
                "detail": ((first_bad or runs[0])["detail"] if len(oks) != len(runs) else ""),
                "rtt": min(rtts) if rtts else None,
                "fp": next((r["fp"] for r in oks if r.get("fp")), None),
                "tls": next((r["tls"] for r in oks if r.get("tls")), None),
            }
            if len(oks) == len(runs):
                verdict = f"[green]работает[/green] {len(oks)}/{len(runs)}"
            elif oks:
                verdict = f"[yellow]нестабилен[/yellow] {len(oks)}/{len(runs)}"
            else:
                verdict = f"[bold red]НЕ работает[/bold red] {len(oks)}/{len(runs)}"
            extras = " | ".join(x for x in [
                _plain(current_res["status"]),
                current_res["detail"] or "",
                current_res["tls"] or "",
                f"{args.kb}KB" if args.kb else "",
                f"hold {args.hold:g}s" if args.hold else "",
                f"{int(current_res['rtt'] * 1000)}ms" if current_res["rtt"] else "",
            ] if x)
            console.print(
                f"  [cyan]{label}:{port}[/cyan] [dim]текущий[/dim] {current_sni}  "
                f"{verdict} [dim]| {extras}[/dim]"
            )
        else:
            console.print(
                f"  [cyan]{label}:{port}[/cyan] [dim]текущий SNI не указан (--current-sni)[/dim]"
            )

        # Эталонный отпечаток серта инбаунда: все SNI должны отдавать его же.
        ref = {"fp": target.get("ref_fp") or (current_res or {}).get("fp")}
        hint = (current_res or {}).get("rtt")

        # ── Фаза 2/2: подбор — ВСЕГДА, без условий ──
        found: List[dict] = []
        rejected_fp: List[dict] = []
        empty_sni: Optional[dict] = None
        ban_detected = False
        ban_detail = ""
        checked = 0
        top_n = 10 ** 6 if args.all else args.top
        batch_size = args.batch_size
        total_sni = len(self.sni_list)

        def _accept(r: dict, name: str, num: int) -> None:
            r = dict(r)
            r["label"] = name
            r["num"] = num
            if ref["fp"] is None and r.get("fp"):
                ref["fp"] = r["fp"]  # эталон = первый успешный отпечаток
            r["cert_match"] = (ref["fp"] is None or r.get("fp") is None
                               or r["fp"] == ref["fp"])
            if not r["cert_match"] and not args.no_cert_check:
                rejected_fp.append(r)
                return
            found.append(r)

        # Шаг 0: без SNI (как в тесте 4). В инбаунд такое не поставишь, поэтому это
        # не кандидат, а два ориентира: честный серт инбаунда (без SNI DPI не режет)
        # и проверка, что сам сервер/маршрут в порядке.
        if not args.no_empty_sni:
            try:
                r0 = await self._probe(ip, port, "", hint_rtt=hint, tcp_ok=True)
                checked += 1
                empty_sni = r0
                if self._is_ok(r0):
                    if ref["fp"] is None and r0.get("fp"):
                        ref["fp"] = r0["fp"]
                elif self._is_connect_level(r0):
                    ban_detected = True
                    ban_detail = r0["status"]
            except Exception as e:
                logger.debug("Probe without SNI failed for %s: %s", ip, e, exc_info=True)

        batches = [self.sni_list[i:i + batch_size] for i in range(0, total_sni, batch_size)]

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      transient=True) as progress:
            task_id = progress.add_task("Фаза 2/2: перебор SNI", total=total_sni)
            for batch in batches:
                if len(found) >= top_n or ban_detected:
                    break

                results = await asyncio.gather(
                    *[self._probe(ip, port, s, hint_rtt=hint, tcp_ok=True) for s in batch],
                    return_exceptions=True,
                )
                checked += len(batch)
                progress.update(task_id, completed=min(checked, total_sni),
                                description=f"Фаза 2/2: перебор SNI "
                                            f"({min(checked, total_sni)}/{total_sni}), "
                                            f"найдено {len(found)}")

                ok_results = [r for r in results if isinstance(r, dict)]

                # Весь батч отвалился на уровне соединения → бан/рейт-лимит (логика теста 4)
                connect_fails = sum(
                    1 for r in results
                    if not isinstance(r, dict) or self._is_connect_level(r)
                )
                if connect_fails == len(batch):
                    ban_detected = True
                    ban_detail = ok_results[0]["status"] if ok_results else "батч целиком упал"
                    break

                # Собираем OK в порядке файла
                for s in batch:
                    if len(found) >= top_n:
                        break
                    for r in ok_results:
                        if r["sni"] == s and self._is_ok(r):
                            _accept(r, s, self.sni_index.get(s, 0))
                            break

        # ── Фаза 3/3: верификация кандидатов (стабильность) ──
        extra = max(0, args.verify - 1)
        if found and extra:
            async def _verify(cand: dict) -> dict:
                oks = 1
                rtts = [cand["rtt"]] if cand.get("rtt") else []
                for _ in range(extra):
                    r = await self._probe(ip, port, cand["label"], hint_rtt=hint, tcp_ok=True)
                    if self._is_ok(r):
                        oks += 1
                        if r.get("rtt"):
                            rtts.append(r["rtt"])
                    else:
                        cand["status"] = r["status"]
                        cand["detail"] = r["detail"]
                cand["ok"] = oks
                cand["runs"] = extra + 1
                cand["stable"] = (oks == extra + 1)
                if rtts:
                    cand["rtt"] = min(rtts)
                return cand

            await _run_with_progress(
                [_verify(c) for c in found],
                f"Фаза 3/3: верификация {len(found)} кандидатов (x{args.verify})",
            )
        else:
            for c in found:
                c["ok"], c["runs"], c["stable"] = 1, 1, True

        # ── Печать результата цели (одной строкой, как в тесте 4) ──
        async with self.print_lock:
            if empty_sni is not None:
                mark = "[green]OK[/green]" if self._is_ok(empty_sni) else _plain(empty_sni["status"])
                fp_note = f" | серт инбаунда {empty_sni['fp']}" if empty_sni.get("fp") else ""
                console.print(f"    [dim]без SNI: {mark}{fp_note}[/dim]")
            if found:
                parts = []
                for c in sorted(found, key=lambda x: (not x["stable"], x["num"])):
                    n_str = f" [dim]#{c['num']}[/dim]" if c["num"] else ""
                    mark = "" if c["stable"] else " [yellow]~[/yellow]"
                    parts.append(f"[bold green]{c['label']}[/bold green]{n_str}{mark}")
                    if len(parts) >= 5:
                        break
                suffix = "  [dim yellow]⚠ бан после[/dim yellow]" if ban_detected else ""
                more = f"  [dim]и ещё {len(found) - len(parts)}[/dim]" if len(found) > len(parts) else ""
                console.print(
                    f"  [cyan]{label}:{port}[/cyan] [dim]проверено {min(checked, total_sni + 1)}[/dim]  "
                    f"[green]✓[/green] {'  '.join(parts)}{more}{suffix}"
                )
            elif ban_detected:
                console.print(
                    f"  [cyan]{label}:{port}[/cyan]  [yellow]⚠ бан/рейт-лимит[/yellow] "
                    f"[dim]({_plain(ban_detail)})[/dim]"
                )
            else:
                console.print(
                    f"  [cyan]{label}:{port}[/cyan]  [red]× SNI не найден[/red] "
                    f"[dim](проверено {min(checked, total_sni + 1)}, все не работают)[/dim]"
                )
            if rejected_fp:
                names = ", ".join(c["label"] for c in rejected_fp[:5])
                console.print(
                    f"    [dim yellow]чужой сертификат (возможен MITM/заглушка), "
                    f"отброшено: {names}[/dim yellow]"
                )

        return {
            "target": ip,
            "port": port,
            "label": label,
            "tcp": True,
            "tcp_detail": "",
            "current_sni": current_sni,
            "current": ({
                "sni": current_sni,
                "status": _plain(current_res["status"]),
                "detail": current_res["detail"],
                "ok": current_res["ok"],
                "runs": current_res["runs"],
                "works": current_res["ok"] == current_res["runs"],
                "rtt_ms": int(current_res["rtt"] * 1000) if current_res.get("rtt") else None,
                "cert_fp": current_res.get("fp"),
            } if current_res else None),
            "reference_cert_fp": ref["fp"],
            "empty_sni": ({
                "status": _plain(empty_sni["status"]),
                "works": self._is_ok(empty_sni),
                "cert_fp": empty_sni.get("fp"),
            } if empty_sni is not None else None),
            "checked": min(checked, total_sni + 1),
            "banned": ban_detected,
            "ban_detail": _plain(ban_detail),
            "picks": [
                {
                    "sni": c["label"],
                    "num": c["num"],
                    "rtt_ms": int(c["rtt"] * 1000) if c.get("rtt") else None,
                    "ok": c.get("ok", 1),
                    "runs": c.get("runs", 1),
                    "stable": c.get("stable", True),
                    "cert_match": c.get("cert_match", True),
                    "tls": c.get("tls"),
                }
                for c in sorted(found, key=lambda x: (not x["stable"], x["num"]))
            ],
            "rejected_cert_mismatch": [c["label"] for c in rejected_fp],
        }


# ── Ввод/вывод ────────────────────────────────────────────────


def load_sni_candidates(path: str, extra: List[str]) -> Tuple[List[str], dict]:
    """Список кандидатов + индекс SNI -> номер в файле (1-based), как в тесте 4."""
    lines: List[str] = []
    if path:
        p = Path(path)
        if not p.exists():
            p = Path(get_resource_path(path))
        if p.exists():
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        else:
            console.print(f"[yellow]Файл со SNI не найден: {path}[/yellow]")
    lines.extend(extra or [])

    sni_list: List[str] = []
    sni_index: dict = {}
    num = 0
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "*" in s:  # в SNI вайлдкарт ставить нельзя
            continue
        s = s.rstrip(".").lower()
        if s in sni_index:
            continue
        num += 1
        sni_index[s] = num
        sni_list.append(s)
    return sni_list, sni_index


def load_targets(args) -> List[dict]:
    targets: List[dict] = []
    for ip in args.ip or []:
        targets.append({"ip": ip, "port": args.port, "sni": args.current_sni or "", "label": ip})

    if args.targets:
        p = Path(args.targets)
        if not p.exists():
            p = Path(get_resource_path(args.targets))
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            console.print(f"[red]Не удалось прочитать {args.targets}: {e}[/red]")
            data = []
        for item in data if isinstance(data, list) else []:
            if not isinstance(item, dict) or not item.get("ip"):
                continue
            targets.append({
                "ip": item["ip"],
                "port": int(item.get("port", args.port)),
                "sni": item.get("sni") or args.current_sni or "",
                "label": item.get("id") or item.get("provider") or item["ip"],
            })
    return targets


def print_summary(results: List[dict], args) -> None:
    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("Цель", style="cyan", no_wrap=True)
    table.add_column("Текущий SNI", no_wrap=True)
    table.add_column("Рекомендуется", style="bold green", no_wrap=True)
    table.add_column("RTT", justify="right")
    table.add_column("Запасные", style="dim", no_wrap=True)

    for res in results:
        picks = res.get("picks") or []
        cur = res.get("current")
        cur_cell = "[dim]—[/dim]"
        if cur:
            cur_cell = (f"[green]{res['current_sni']}[/green]" if cur["works"]
                        else f"[bold red]{res['current_sni']}[/bold red]")
        best = picks[0] if picks else None
        table.add_row(
            f"{res['label']}:{res['port']}",
            cur_cell,
            best["sni"] if best else "[red]не найден[/red]",
            f"{best['rtt_ms']}ms" if best and best.get("rtt_ms") else "-",
            ", ".join(p["sni"] for p in picks[1:4]) or "—",
        )
    console.print()
    console.print(table)

    for res in results:
        picks = res.get("picks") or []
        if not picks:
            continue
        best = picks[0]["sni"]
        console.print(
            f"\n[dim]Для инбаунда {res['label']}:{res['port']} — вставьте в tlsSettings:[/dim] "
            f'[bold]"serverName": "{best}"[/bold]'
        )
        cur = res.get("current")
        if cur and not cur["works"]:
            console.print(
                f"[yellow]Текущий SNI {res['current_sni']} не работает "
                f"({cur['status']}) — его нужно менять.[/yellow]"
            )
        elif cur and cur["works"]:
            console.print(
                f"[dim]Текущий SNI {res['current_sni']} работает — менять не обязательно, "
                f"список выше — замена на случай блокировки.[/dim]"
            )


def write_outputs(results: List[dict], args) -> int:
    picked: List[str] = []
    for res in results:
        for p in res.get("picks") or []:
            if p["sni"] not in picked:
                picked.append(p["sni"])

    if args.output:
        payload = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "probe": args.probe,
            "kb": args.kb,
            "hold": args.hold,
            "verify": args.verify,
            "cert_check": not args.no_cert_check,
            "targets": results,
            "picked": picked,
        }
        Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                                     encoding="utf-8")
        console.print(f"[dim]JSON-отчёт: {args.output}[/dim]")

    if args.out_txt:
        Path(args.out_txt).write_text("\n".join(picked) + ("\n" if picked else ""),
                                      encoding="utf-8")
        console.print(f"[dim]Список рабочих SNI ({len(picked)}): {args.out_txt}[/dim]")

    return len(picked)


def parse_args(argv: Optional[List[str]] = None):
    p = argparse.ArgumentParser(
        description="Подбор рабочего SNI для TLS/VLESS-инбаунда (всегда, без условия блокировки).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Примеры:\n"
                "  python3 sni_picker.py --ip 1.2.3.4 -c current.example.com\n"
                "  python3 sni_picker.py --ip 1.2.3.4 --port 8443 --all --verify 3\n"
                "  python3 sni_picker.py --targets tcp16.json --top 5\n"),
    )
    p.add_argument("--ip", action="append", help="IP сервера с инбаундом (можно повторять)")
    p.add_argument("--port", type=int, default=443, help="порт инбаунда (по умолчанию 443)")
    p.add_argument("-c", "--current-sni", default="", help="SNI, стоящий в инбаунде сейчас")
    p.add_argument("--targets", help="JSON с целями в формате tcp16.json")
    p.add_argument("--sni-file", default="whitelist_sni.txt", help="файл со SNI-кандидатами")
    p.add_argument("--sni", action="append", help="дополнительный SNI-кандидат (можно повторять)")
    p.add_argument("--probe", choices=["tls", "fat", "http"], default="tls",
                   help="tls: handshake+удержание (как VLESS); fat: +объём данных; "
                        "http: родная проба тестов 3/4")
    p.add_argument("--kb", type=int, default=None,
                   help="сколько КБ лить в режиме fat (по умолчанию 40)")
    p.add_argument("--hold", type=float, default=3.0,
                   help="сколько секунд держать соединение после handshake (0 = не держать)")
    p.add_argument("--top", type=int, default=getattr(config, "SNI_TOP_N", _DEFAULT_SNI_TOP_N),
                   help="сколько рабочих SNI искать (config.SNI_TOP_N)")
    p.add_argument("--all", action="store_true",
                   help="проверить весь список, а не останавливаться на top-N")
    p.add_argument("--batch-size", type=int,
                   default=getattr(config, "SNI_BATCH_SIZE", _DEFAULT_SNI_BATCH_SIZE),
                   help="размер батча (config.SNI_BATCH_SIZE)")
    p.add_argument("--verify", type=int, default=2, help="сколько раз проверять каждый SNI")
    p.add_argument("--concurrency", type=int, default=getattr(config, "MAX_CONCURRENT", 50),
                   help="параллельные пробы (config.MAX_CONCURRENT)")
    p.add_argument("--tls", choices=["auto", "TLSv1.2", "TLSv1.3"], default="auto",
                   help="версия TLS")
    p.add_argument("--no-cert-check", action="store_true",
                   help="не отбрасывать SNI, по которым пришёл другой сертификат")
    p.add_argument("--no-empty-sni", action="store_true", help="не проверять вариант без SNI")
    p.add_argument("-o", "--output", default="sni_result.json", help="JSON-отчёт (пусто = не писать)")
    p.add_argument("--out-txt", default="sni_picked.txt", help="текстовый список рабочих SNI")
    p.add_argument("-v", "--verbose", action="store_true", help="подробные логи")

    args = p.parse_args(argv)
    if args.kb is None:
        args.kb = 40 if args.probe == "fat" else 0
    args.verify = max(1, args.verify)
    args.top = max(1, args.top)
    args.batch_size = max(1, args.batch_size)
    args.concurrency = max(1, args.concurrency)
    if not args.ip and not args.targets:
        p.error("укажите --ip ИЛИ --targets")
    return args


async def run(args) -> int:
    sni_list, sni_index = load_sni_candidates(args.sni_file, args.sni or [])
    targets = load_targets(args)

    if not targets:
        console.print("[red]Нет целей для проверки.[/red]")
        return 2
    if not sni_list:
        console.print("[red]Пустой список SNI-кандидатов (--sni-file / --sni).[/red]")
        return 2

    goal = "все" if args.all else f"топ-{args.top}"
    vol = f" | объём: {args.kb}KB" if args.kb else ""
    hold = f" | hold: {args.hold:g}s" if args.hold else ""
    console.print(
        f"\n[bold]Подбор рабочего SNI для инбаунда[/bold]  "
        f"[dim]целей: {len(targets)} | SNI: {len(sni_list)} | батч: {args.batch_size}"
        f" | режим: {args.probe}{vol}{hold}"
        f" | перепроверка: x{args.verify} | цель: {goal}[/dim]\n"
    )

    picker = SniPicker(args, sni_list, sni_index)
    results = []
    for target in targets:  # последовательно: не создаём себе же шум в замерах RTT
        results.append(await picker.pick_for_target(target))

    print_summary(results, args)
    picked = write_outputs(results, args)
    return 0 if picked else 2


def main() -> int:
    config.load_config()  # как в dpi_detector.py: сначала конфиг, потом аргументы
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    try:
        install_crlf_stdout()
    except Exception:
        pass
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано пользователем.[/yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
