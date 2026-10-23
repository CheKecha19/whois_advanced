"""Excel/CSV/JSON output, input auditing and comparison of report snapshots."""

import csv
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path

import pandas as pd

from providers import GEO_FIELDS, NETWORK_FIELDS, MISSING, normalize_asn
from storage import atomic_output

FIELDS = ["ip", *GEO_FIELDS, *NETWORK_FIELDS, "asn_description", "success", "completeness",
          "missing_fields", "data_source", "source_url", "retrieved_at", "rdap_status",
          "request_status", "error_type", "error_message", "cache_hit", "resumed",
          "field_sources", "source_details", "events"]
COMPARE_FIELDS = (*GEO_FIELDS, *NETWORK_FIELDS)


def read_input(path):
    addresses, errors = {}, []
    stats = dict(lines=0, candidates=0, valid=0, duplicates=0, rejected=0)
    with open(path, encoding="utf-8-sig") as source:
        for number, line in enumerate(source, 1):
            stats["lines"] += 1
            value = line.split("#", 1)[0].strip()
            if not value:
                continue
            stats["candidates"] += 1
            try:
                address = str(ipaddress.ip_address(value))
                if "%" in value:
                    raise ValueError("Scoped IPv6")
                if address in addresses:
                    stats["duplicates"] += 1
                addresses[address] = None
            except ValueError:
                errors.append({"line": number, "value": value, "error": "invalid_ip"})
    stats.update(valid=len(addresses), rejected=len(errors))
    return list(addresses), stats, errors


def excel_text(value):
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, allow_nan=False)
    if isinstance(value, str):
        value = "".join(c for c in value if ord(c) >= 32 or c in "\n\r\t")
        if len(value) > 32700:
            value = value[:32670] + " [truncated; use JSON]"
        if value.startswith(("=", "+", "-", "@")):
            value = "'" + value
    return value


def load_report(path):
    path = Path(path)
    extension = path.suffix.lower()
    if extension == ".json":
        with path.open(encoding="utf-8") as source:
            data = json.load(source)
        records = data.get("records") if isinstance(data, dict) else data
    elif extension == ".csv":
        with path.open(encoding="utf-8-sig", newline="") as source:
            records = list(csv.DictReader(source))
    elif extension == ".xlsx":
        records = pd.read_excel(path, sheet_name="Все IP-адреса", keep_default_na=False, dtype=str).to_dict("records")
    else:
        raise ValueError("Отчёт должен иметь расширение .json, .csv или .xlsx")
    if not isinstance(records, list):
        raise ValueError("Отчёт не содержит списка records")
    result, seen = [], set()
    for row in records:
        if not isinstance(row, dict) or "ip" not in row or "success" not in row:
            raise ValueError("В отчёте нужны колонки ip и success")
        row = dict(row)
        row["ip"] = str(ipaddress.ip_address(row["ip"]))
        if row["ip"] in seen:
            raise ValueError(f"Повторный IP в отчёте: {row['ip']}")
        seen.add(row["ip"])
        if extension != ".json":
            for key, value in row.items():
                if isinstance(value, str) and value.startswith(("'=", "'+", "'-", "'@")):
                    row[key] = value[1:]
        result.append(row)
    return result


def compare_records(previous, current, expected_addresses=None):
    """Compare only observed data; missing data is not evidence of an owner change."""
    before, after = ({row["ip"]: row for row in records} for records in (previous, current))
    changes = []
    for ip in dict.fromkeys([*before, *after]):
        old, new = before.get(ip), after.get(ip)
        if new is None and expected_addresses is not None and ip in expected_addresses:
            # An interrupted lookup is not evidence that an address was removed.
            continue
        if old is None or new is None:
            changes.append(dict(ip=ip, type="added" if old is None else "removed", field="", before="", after=""))
            continue
        for field in COMPARE_FIELDS:
            left, right = old.get(field, MISSING), new.get(field, MISSING)
            left, right = left or MISSING, right or MISSING
            if field == "asn":
                left, right = normalize_asn(left), normalize_asn(right)
            if left == right:
                continue
            kind = "data_available" if left == MISSING else "data_missing" if right == MISSING else "changed"
            changes.append(dict(ip=ip, type=kind, field=field, before=left, after=right))
    return changes


def build_summary(records, input_stats, started, ended, interrupted=False):
    total = len(records)
    successful = sum(row["success"] == "Yes" for row in records)
    summary = dict(input_stats)
    summary.update(processed=total, successful=successful,
                   failed=sum(row["completeness"] == "failed" for row in records),
                   skipped=sum(row["completeness"] == "skipped" for row in records),
                   partial=sum(row["completeness"] == "partial" for row in records),
                   full=sum(row["completeness"] == "full" for row in records),
                   cached=sum(bool(row["cache_hit"]) for row in records),
                   resumed=sum(bool(row["resumed"]) for row in records),
                   rdap_failed=sum(row["rdap_status"] == "failed" for row in records),
                   success_percent=round(successful / total * 100, 1) if total else 0,
                   started_at=started.isoformat(), ended_at=ended.isoformat(),
                   duration_seconds=(ended - started).total_seconds(), interrupted=interrupted)
    for field in ("organization", "country", "asn"):
        summary[f"unique_{field}"] = len({row[field] for row in records if row[field] != MISSING})
    return summary


def write_report(path, records, summary, input_errors=(), changes=None, overwrite=False, format=None):
    path = Path(path)
    format = format or path.suffix.lower().lstrip(".")
    if format not in ("xlsx", "csv", "json"):
        raise ValueError("Поддерживаются xlsx, csv, json")
    with atomic_output(path, overwrite=overwrite, binary=format == "xlsx") as target:
        if format == "json":
            json.dump(dict(schema_version=2, version="1.2.0", summary=summary, records=records,
                           input_errors=list(input_errors), changes=changes or []), target,
                      ensure_ascii=False, allow_nan=False, indent=2)
        elif format == "csv":
            target.write("\ufeff")
            writer = csv.DictWriter(target, fieldnames=FIELDS)
            writer.writeheader()
            for row in records:
                writer.writerow({field: excel_text(row.get(field, MISSING)) for field in FIELDS})
        else:
            frame = pd.DataFrame(records, columns=FIELDS).fillna(MISSING)
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
            sheets["Успешные запросы"] = frame[frame["success"] == "Yes"]
            sheets["Сводка"] = pd.DataFrame(list(summary.items()), columns=["Метрика", "Значение"])
            sheets["Ошибки входа"] = pd.DataFrame(input_errors, columns=["line", "value", "error"])
            if changes is not None:
                sheets["Изменения"] = pd.DataFrame(changes, columns=["ip", "type", "field", "before", "after"])
            with pd.ExcelWriter(target, engine="openpyxl") as writer:
                for name, data in sheets.items():
                    data.map(excel_text).to_excel(writer, sheet_name=name, index=False)
                    sheet = writer.sheets[name]
                    sheet.freeze_panes = "A2"
                    sheet.auto_filter.ref = sheet.dimensions
                    for column in sheet.columns:
                        width = min(65, max(15, max(len(str(c.value or "")) for c in column) + 2))
                        sheet.column_dimensions[column[0].column_letter].width = width


def save_to_single_excel(whois_results, output_path, started_at=None, ended_at=None, overwrite=False):
    """Compatibility entry point; CLI supplies the full input audit separately."""
    started = started_at or datetime.now(timezone.utc)
    ended = ended_at or datetime.now(timezone.utc)
    summary = build_summary(whois_results, {}, started, ended)
    write_report(output_path, whois_results, summary, overwrite=overwrite, format="xlsx")
    return True
