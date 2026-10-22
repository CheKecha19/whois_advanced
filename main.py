"""IP enrichment and Excel reporting. Run python main.py --help."""

import argparse
from datetime import datetime, timezone
import ipaddress
import math
from pathlib import Path
import sys
import time

import pandas as pd
import requests

__version__ = "1.1.0"
MISSING = "N/A"
FIELDS = ["ip", "organization", "country", "city", "region", "netname", "asn",
          "asn_description", "isp", "postal_code", "timezone", "data_source",
          "success", "request_status", "error_type", "error_message"]
PROVIDERS = (
    ("ipapi.co", "https://ipapi.co/{ip}/json/", {"organization": "org", "country": "country_name"}),
    ("ipwhois.app", "https://ipwhois.app/json/{ip}", {"organization": "org", "country": "country"}),
)


def read_ips_from_txt(file_path):
    """Canonicalize IPv4/IPv6, ignore comments, preserve first-seen order."""
    addresses = {}
    with open(file_path, encoding="utf-8-sig") as source:
        for number, line in enumerate(source, 1):
            value = line.split("#", 1)[0].strip()
            if not value:
                continue
            try:
                address = ipaddress.ip_address(value)
                if "%" in value:
                    raise ValueError("Scoped IPv6 is not supported")
                addresses[str(address)] = None
            except ValueError:
                print(f"Строка {number}: неверный IP {value!r}", file=sys.stderr)
    return list(addresses)


def clean(value):
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return MISSING
    value = " ".join(str(value).split())
    return MISSING if value.lower() in ("", "none", "null", "n/a") else value


def get_comprehensive_whois_info(ip_address, session=None, timeout=10, retries=2, backoff=1):
    """Try providers in order; retry transient failures with bounded backoff."""
    address = ipaddress.ip_address(ip_address)
    result = dict.fromkeys(FIELDS, MISSING)
    result.update(ip=str(address), success="No", request_status="failed",
                  error_type="no_data", error_message="", data_source=MISSING)
    if not address.is_global or address.is_multicast:
        result.update(request_status="skipped", error_type="non_public_ip",
                      error_message="Для локального/служебного IP публичные API не вызываются")
        return result
    owned = session is None
    session = session or requests.Session()
    errors = []
    try:
        for host, template, mapping in PROVIDERS:
            for attempt in range(retries + 1):
                retryable, retry_after = False, None
                status_label = "failed"
                try:
                    with session.get(template.format(ip=address), timeout=timeout) as response:
                        status = response.status_code
                        status_label = f"HTTP {status}"
                        if status != 200:
                            kind, message = f"http_{status}", status_label
                            retryable = status == 429 or status in (500, 502, 503, 504)
                            try:
                                seconds = float(response.headers.get("Retry-After", "nan"))
                                if math.isfinite(seconds):
                                    retry_after = min(60, max(0, seconds))
                            except ValueError:
                                pass
                        else:
                            data = response.json()
                            if not isinstance(data, dict) or not data:
                                kind, message = "invalid_response", "Ожидался непустой JSON-объект"
                            elif data.get("error") or data.get("reserved") or data.get("success") is False:
                                kind, message = "api_error", clean(data.get("reason") or data.get("message") or "API отклонил запрос")
                            else:
                                parsed = {field: clean(data.get(mapping.get(field, field)))
                                          for field in ("organization", "country", "city", "region", "asn", "isp", "timezone")}
                                parsed["postal_code"] = clean(data.get("postal"))
                                if any(parsed[k] != MISSING for k in ("organization", "country", "asn", "isp")):
                                    result.update(parsed)
                                    result.update(success="Yes", request_status="HTTP 200", data_source=host,
                                                  error_type="", error_message="; ".join(errors))
                                    return result
                                kind, message = "no_data", "Ответ не содержит сетевых или географических данных"
                except requests.Timeout:
                    kind, message, retryable = "timeout", "Превышен таймаут", True
                except requests.ConnectionError:
                    kind, message, retryable = "connection_error", "Ошибка соединения/прокси/TLS", True
                except ValueError:
                    kind, message = "invalid_json", "Некорректный JSON"
                except requests.RequestException as error:
                    kind, message = "request_error", type(error).__name__
                errors.append(f"{host} (попытка {attempt + 1}): {message}")
                result.update(error_type=kind, request_status=status_label if kind.startswith("http_") else kind)
                if not retryable or attempt == retries:
                    break
                time.sleep(retry_after if retry_after is not None else min(backoff * 2 ** attempt, 60))
        result["error_message"] = "; ".join(errors)
        return result
    finally:
        if owned:
            session.close()


def excel_text(value):
    """Keep external values as text rather than executable spreadsheet formulas."""
    if isinstance(value, str):
        value = "".join(c for c in value if ord(c) >= 32 or c in "\n\r\t")
        return "'" + value if value.startswith(("=", "+", "-", "@")) else value
    return value


def save_to_single_excel(whois_results, output_path, started_at=None, ended_at=None, overwrite=False):
    """Always write six sheets, with real timing and unknowns excluded from counts."""
    started_at = started_at or datetime.now(timezone.utc)
    ended_at = ended_at or datetime.now(timezone.utc)
    frame = pd.DataFrame(whois_results, columns=FIELDS).fillna(MISSING)
    successful = frame[frame["success"] == "Yes"]
    sheets = {"Все IP-адреса": frame}
    for name, key in (("По организациям", "organization"), ("По странам", "country"), ("По ASN", "asn")):
        valid = frame[frame[key] != MISSING]
        aggregations = {"ip": "count"}
        for column in ("organization", "country", "asn"):
            if column != key:
                aggregations[column] = lambda values: ", ".join(dict.fromkeys(v for v in values if v != MISSING))
        sheets[name] = (valid.groupby(key, sort=False).agg(aggregations)
                        .rename(columns={"ip": "count_ips"}).reset_index()
                        .sort_values("count_ips", ascending=False))
    sheets["Успешные запросы"] = successful
    sheets["Сводка"] = pd.DataFrame({
        "Метрика": ["Всего обработано IP-адресов", "Успешных запросов", "Процент успешных запросов",
                    "Уникальных организаций", "Уникальных стран", "Уникальных ASN",
                    "Время начала (UTC)", "Время окончания (UTC)", "Длительность (сек.)"],
        "Значение": [len(frame), len(successful), f"{len(successful) / len(frame) * 100:.1f}%" if len(frame) else "0.0%",
                     *[frame.loc[frame[k] != MISSING, k].nunique() for k in ("organization", "country", "asn")],
                     started_at.isoformat(), ended_at.isoformat(), (ended_at - started_at).total_seconds()],
    })
    with open(output_path, "wb" if overwrite else "xb") as target:
        with pd.ExcelWriter(target, engine="openpyxl") as writer:
            for name, data in sheets.items():
                data.map(excel_text).to_excel(writer, sheet_name=name, index=False)
                sheet = writer.sheets[name]
                sheet.freeze_panes = "A2"
                sheet.auto_filter.ref = sheet.dimensions
                for column in sheet.columns:
                    width = min(65, max(15, max(len(str(c.value or "")) for c in column) + 2))
                    sheet.column_dimensions[column[0].column_letter].width = width
    return True


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("ожидалось конечное число > 0")
    return number


def nonnegative_float(value):
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("ожидалось конечное число >= 0")
    return number


def nonnegative_int(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("ожидалось целое число >= 0")
    return number


def main(argv=None):
    directory = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Сбор данных о публичных IPv4/IPv6 и экспорт в Excel")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--input", type=Path, default=directory / "ip_list.txt")
    parser.add_argument("--output", type=Path, help="Путь к Excel-отчёту (по умолчанию — имя с UTC-временем)")
    parser.add_argument("--overwrite", action="store_true", help="Разрешить замену существующего отчёта")
    parser.add_argument("--timeout", type=positive_float, default=10)
    parser.add_argument("--delay", type=nonnegative_float, default=1)
    parser.add_argument("--retries", type=nonnegative_int, default=2, help="Повторы после первого запроса")
    args = parser.parse_args(argv)
    started = datetime.now(timezone.utc)
    output = args.output or directory / f"WHOIS_Analysis_Report_{started:%Y%m%d_%H%M%S_%f}.xlsx"
    if output.resolve() == args.input.resolve():
        print("Входной файл и отчёт должны иметь разные пути", file=sys.stderr)
        return 1
    if output.exists() and not args.overwrite:
        print(f"Отчёт уже существует: {output}. Выберите другое имя или --overwrite", file=sys.stderr)
        return 1
    try:
        addresses = read_ips_from_txt(args.input)
        if not addresses:
            print("Входной файл не содержит корректных IP", file=sys.stderr)
            return 1
        results = []
        with requests.Session() as session:
            for index, address in enumerate(addresses, 1):
                result = get_comprehensive_whois_info(address, session, args.timeout, args.retries)
                results.append(result)
                print(f"[{index}/{len(addresses)}] {address}: {result['success']} — {result['organization']}")
                if result["error_message"]:
                    print(result["error_message"], file=sys.stderr)
                if index < len(addresses):
                    time.sleep(args.delay)
        save_to_single_excel(results, output, started, datetime.now(timezone.utc), args.overwrite)
        count = sum(row["success"] == "Yes" for row in results)
        print(f"Успешно: {count}/{len(results)}. Отчёт: {output}")
        return 0 if count == len(results) else 2
    except (OSError, ValueError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
