"""whois_advanced v1.2: resumable IP enrichment and comparison reports."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import sys
import time

import requests

from providers import LookupClient, PROVIDERS
from reporting import (build_summary, compare_records, load_report, read_input,
                       save_to_single_excel, write_report)
from storage import StateStore
from console import Progress

__version__ = "1.2.0"


def read_ips_from_txt(path):
    addresses, _, errors = read_input(path)
    for error in errors:
        print(f"Строка {error['line']}: неверный IP {error['value']!r}", file=sys.stderr)
    return addresses


def get_comprehensive_whois_info(ip_address, session=None, timeout=10, retries=2):
    """For batch operations reuse LookupClient to preserve provider cooldowns."""
    if session is None:
        with requests.Session() as session:
            return LookupClient(session, timeout, retries).lookup(ip_address)
    return LookupClient(session, timeout, retries).lookup(ip_address)


def number(value, minimum=0):
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise argparse.ArgumentTypeError(f"ожидалось конечное число >= {minimum}")
    return result


def positive(value):
    result = number(value)
    if result == 0:
        raise argparse.ArgumentTypeError("ожидалось число > 0")
    return result


def integer(value):
    result = int(value)
    if result < 0:
        raise argparse.ArgumentTypeError("ожидалось целое число >= 0")
    return result


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def reusable(row, rdap):
    return row and (row["request_status"] == "skipped" or
                    (row["success"] == "Yes" and (not rdap or row["rdap_status"] == "success")))


def parser_for_cli():
    parser = argparse.ArgumentParser(description="IPv4/IPv6: API, RDAP, кэш, возобновление и отчёты")
    parser.add_argument("--version", action="version", version=__version__)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--input", type=Path, help="UTF-8-файл IP (по умолчанию ip_list.txt рядом со скриптом)")
    inputs.add_argument("--retry-failed", type=Path, help="Повторить ошибки из JSON/CSV/XLSX-отчёта")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--format", choices=("xlsx", "csv", "json"))
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--timeout", type=positive, default=10)
    parser.add_argument("--delay", type=number, default=1)
    parser.add_argument("--retries", type=integer, default=2)
    parser.add_argument("--providers", nargs="+", choices=tuple(PROVIDERS), default=list(PROVIDERS))
    parser.add_argument("--rdap", action="store_true", help="Дополнить регистрационными данными RDAP")
    parser.add_argument("--batch", choices=("auto", "off", "on"), default="auto",
                        help="IPWHOIS Pro bulk: auto использует IPWHOIS_API_KEY, on требует ключ")
    parser.add_argument("--batch-size", type=integer, default=100, help="Адресов в пакете, 1–100")
    parser.add_argument("--state-dir", type=Path, default=Path(__file__).resolve().parent / ".whois")
    parser.add_argument("--resume", action="store_true", help="Продолжить тот же список и настройки источников")
    parser.add_argument("--cache-ttl", type=number, default=86400, help="Срок кэша в секундах; по умолчанию сутки")
    parser.add_argument("--no-cache", action="store_true", help="Не читать и не записывать кэш")
    parser.add_argument("--refresh", action="store_true", help="Не читать кэш, но обновить его")
    parser.add_argument("--compare", type=Path, help="Сравнить результат с предыдущим JSON/CSV/XLSX")
    parser.add_argument("--log", type=Path, help="Машинный журнал JSONL (создаётся до начала запросов)")
    parser.add_argument("--quiet", action="store_true", help="Не показывать прогресс каждого адреса")
    parser.add_argument("--verbose", action="store_true", help="Подробные результаты и ошибки каждого IP")
    return parser


def same_path(left, right):
    return left.resolve() == right.resolve() or (left.exists() and right.exists() and left.samefile(right))


def preflight(args, output, inputs):
    destinations = [output] + ([args.log] if args.log else [])
    for index, destination in enumerate(destinations):
        if destination.exists() and (not args.overwrite or destination.is_dir()):
            raise ValueError(f"Файл уже существует: {destination}; используйте --overwrite")
        if not destination.parent.is_dir():
            raise ValueError(f"Нет выходного каталога: {destination.parent}")
        if any(same_path(destination, source) for source in inputs):
            raise ValueError("Выходной файл не должен совпадать с входным отчётом или списком")
        if any(same_path(destination, other) for other in destinations[:index]):
            raise ValueError("Отчёт и журнал должны иметь разные пути")
        if destination.resolve().is_relative_to(args.state_dir.resolve()):
            raise ValueError("Отчёты и журналы нужно сохранять вне служебного --state-dir")


def main(argv=None):
    args = parser_for_cli().parse_args(argv)
    directory = Path(__file__).resolve().parent
    started = datetime.now(timezone.utc)
    format = args.format or (args.output.suffix.lower().lstrip(".") if args.output else "xlsx")
    output = args.output or directory / f"WHOIS_Analysis_Report_{started:%Y%m%d_%H%M%S_%f}.{format}"
    source = args.retry_failed or args.input or directory / "ip_list.txt"
    store = log = None
    results, interrupted = [], False
    try:
        if format not in ("xlsx", "csv", "json") or output.suffix.lower() != f".{format}":
            raise ValueError("Расширение отчёта должно соответствовать --format: xlsx, csv или json")
        if format == "csv" and args.compare and not args.log:
            raise ValueError("Для сравнения при CSV укажите --log changes.jsonl либо выберите JSON/XLSX")
        if args.resume and args.refresh:
            raise ValueError("--resume и --refresh несовместимы: выберите продолжение или обновление")
        if not 1 <= args.batch_size <= 100:
            raise ValueError("--batch-size должен быть от 1 до 100")
        bulk_key = os.environ.get("IPWHOIS_API_KEY") if args.batch != "off" else None
        if args.batch == "on" and not bulk_key:
            raise ValueError("Пакетному API нужен ключ IPWHOIS_API_KEY в переменных окружения; --batch off работает без ключа")
        preflight(args, output, [source] + ([args.compare] if args.compare else []))
        previous = load_report(args.compare) if args.compare else None
        if args.retry_failed:
            rows = load_report(args.retry_failed)
            addresses = [r["ip"] for r in rows if r.get("request_status") != "skipped" and
                         (r["success"] != "Yes" or r.get("rdap_status") == "failed")]
            stats = dict(lines=len(rows), candidates=len(addresses), valid=len(addresses), duplicates=0, rejected=0)
            errors = []
            if any(r.get("rdap_status") == "failed" for r in rows):
                args.rdap = True
        else:
            addresses, stats, errors = read_input(source)
        if not addresses and not errors:
            print("Нет адресов для обработки: вход пуст или повторять нечего.")
            return 0 if args.retry_failed else 1
        if args.verbose and not args.quiet:
            for error in errors:
                print(f"Строка {error['line']}: неверный IP {error['value']!r}", file=sys.stderr)
        configuration = dict(schema=2, providers=list(dict.fromkeys(args.providers)), rdap=args.rdap, bulk=bool(bulk_key))
        run_key = fingerprint(dict(configuration, addresses=addresses))
        store = StateStore(args.state_dir)
        if args.log:
            log = args.log.open("w" if args.overwrite else "x", encoding="utf-8")

        def emit(kind, payload):
            if log:
                log.write(json.dumps(dict(type=kind, at=datetime.now(timezone.utc).isoformat(),
                                          **payload), ensure_ascii=False, allow_nan=False) + "\n")
                log.flush()

        emit("start", dict(version=__version__, run_key=run_key, input_stats=stats, input_errors=errors))
        clock = time.monotonic()
        progress = Progress(len(addresses), args.quiet, args.verbose)
        client = None
        try:
            with requests.Session() as session:
                session.headers["User-Agent"] = "whois_advanced/1.2"
                client = LookupClient(session, args.timeout, args.retries, configuration["providers"], args.rdap, bulk_key)
                for offset in range(0, len(addresses), args.batch_size):
                    pending = []
                    for address in addresses[offset:offset + args.batch_size]:
                        cache_key = fingerprint(dict(configuration, ip=address))
                        result = store.checkpoint(run_key, address) if args.resume else None
                        if reusable(result, args.rdap):
                            result.update(resumed=True, cache_hit=False)
                        else:
                            result = None
                        if result is None and not (args.no_cache or args.refresh or args.retry_failed):
                            result = store.cached(cache_key, args.cache_ttl)
                            if result is not None:
                                result.update(cache_hit=True, resumed=False)
                        pending.append((address, cache_key, result))
                    if bulk_key:
                        client.prepare_batch([address for address, _, result in pending if result is None])
                    for address, cache_key, result in pending:
                        fresh = result is None
                        if fresh:
                            result = client.lookup(address)
                        store.save(run_key, cache_key, result,
                                   cacheable=fresh and not args.no_cache and result["success"] == "Yes" and reusable(result, args.rdap))
                        results.append(result)
                        emit("result", dict(record=result))
                        progress.update(result)
                        if len(results) < len(addresses) and fresh and "ipwhois-pro" not in result["source_details"]:
                            time.sleep(args.delay)
                    if bulk_key and offset + args.batch_size < len(addresses):
                        time.sleep(args.delay)
        except KeyboardInterrupt:
            interrupted = True
            print("Прервано: сохраняю обработанные адреса. Продолжение: --resume с тем же списком.", file=sys.stderr)
        finally:
            progress.close()
        summary = build_summary(results, stats, started, datetime.now(timezone.utc), interrupted)
        summary.update(http_requests=client.request_count if client else 0, batch_enabled=bool(bulk_key))
        changes = compare_records(previous, results, addresses) if previous is not None else None
        write_report(output, results, summary, errors, changes, args.overwrite, format)
        emit("summary", dict(summary=summary, changes=changes or [], output=str(output)))
        print(f"Обработано {len(results)}/{len(addresses)} | успешно {summary['successful']} | "
              f"ошибок {summary['failed']} | пропущено {summary['skipped']} | неверных строк {stats['rejected']}")
        print(f"Кэш {summary['cached']} | продолжено {summary['resumed']} | "
              f"HTTP {summary['http_requests']} | RDAP-ошибок {summary['rdap_failed']} | {time.monotonic() - clock:.1f} сек.")
        print(f"Отчёт: {output}")
        if interrupted:
            return 130
        return 2 if stats["rejected"] or summary["failed"] or summary["skipped"] or summary["rdap_failed"] else 0
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1
    finally:
        if log:
            log.close()
        if store:
            store.close()


if __name__ == "__main__":
    sys.exit(main())
