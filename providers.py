"""Provider adapters, shared cooldowns and IANA-based RDAP discovery."""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import ipaddress
import math
import time
from urllib.parse import urljoin, urlsplit

import requests

MISSING = "N/A"
GEO_FIELDS = ("organization", "country", "city", "region", "asn", "isp", "postal_code", "timezone")
NETWORK_FIELDS = ("netname", "network_start", "network_end", "network_handle",
                  "registered_organization", "registration_country")
PROVIDERS = {
    "ipapi": ("https://ipapi.co/{ip}/json/", {"organization": "org", "country": "country_name", "postal_code": "postal"}),
    "ipwhois": ("https://ipwhois.app/json/{ip}", {"organization": "org", "postal_code": "postal"}),
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def clean(value):
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return MISSING
    text = " ".join(str(value).split())
    return MISSING if text.lower() in ("", "none", "null", "n/a", "nan") else text


def normalize_asn(value):
    text = clean(value).upper()
    digits = text[2:] if text.startswith("AS") else text
    if digits.isascii() and digits.isdigit() and 0 < int(digits) <= 4294967295:
        return f"AS{int(digits)}"
    return MISSING


def retry_seconds(value, now=None):
    """Retry-After may be seconds or an HTTP date; never shorten the server delay."""
    try:
        number = float(value)
        if math.isfinite(number):
            return max(0, number)
    except (ValueError, TypeError):
        pass
    try:
        date = parsedate_to_datetime(value)
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        return max(0, date.timestamp() - (time.time() if now is None else now))
    except (TypeError, ValueError, OverflowError):
        return None


class LookupClient:
    def __init__(self, session, timeout=10, retries=2, providers=("ipapi", "ipwhois"), rdap=False, bulk_key=None):
        self.session = session
        self.timeout = timeout
        self.retries = retries
        self.providers = tuple(providers)
        self.rdap = rdap
        self.cooldowns = {}
        self.bootstrap = {}
        self.bulk_key = bulk_key
        self.bulk_records = {}
        self.bulk_attempted = set()
        self.bulk_events = []
        self.request_count = 0
        self.final_urls = {}

    def fetch(self, url, events, payload=None, follow_rdap=False, redirects=0):
        host = urlsplit(url).hostname
        if urlsplit(url).scheme != "https" or not host:
            raise ValueError("Источники должны использовать HTTPS")
        remaining = self.cooldowns.get(host, 0) - time.monotonic()
        if remaining > 0:
            events.append(self.event(url, "cooldown", f"Источник на паузе ещё {remaining:.0f} сек."))
            return None
        for attempt in range(self.retries + 1):
            retryable = False
            try:
                self.request_count += 1
                if payload is None:
                    request = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                else:
                    request = self.session.post(url, params={"key": self.bulk_key}, json=payload,
                                                timeout=self.timeout, allow_redirects=False)
                with request as response:
                    status = response.status_code
                    if follow_rdap and status in (301, 302, 303, 307, 308):
                        destination = urljoin(url, response.headers.get("Location", ""))
                        parts = urlsplit(destination)
                        if redirects >= 5 or destination == url or parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
                            events.append(self.event(url, "redirect_error", "Отклонён небезопасный/зацикленный RDAP redirect"))
                            return None
                        data = self.fetch(destination, events, follow_rdap=True, redirects=redirects + 1)
                        if data is not None:
                            self.final_urls[url] = self.final_urls.get(destination, destination)
                        return data
                    if status == 200:
                        data = response.json()
                        if (isinstance(data, dict) and data) or (payload is not None and isinstance(data, list) and data):
                            return data
                        kind, message = "invalid_response", "Ожидался непустой JSON-объект"
                    else:
                        kind, message = f"http_{status}", f"HTTP {status}"
                        wait = retry_seconds(response.headers.get("Retry-After"))
                        if status == 429 or (status == 503 and wait is not None):
                            self.cooldowns[host] = time.monotonic() + (wait if wait is not None else 60)
                        elif status in (401, 403):
                            self.cooldowns[host] = time.monotonic() + 300
                        else:
                            retryable = status in (500, 502, 503, 504)
            except requests.exceptions.SSLError:
                kind, message = "tls_error", "Ошибка проверки TLS-сертификата"
            except requests.Timeout:
                kind, message, retryable = "timeout", "Превышен таймаут", True
            except requests.ConnectionError:
                kind, message, retryable = "connection_error", "Ошибка соединения или прокси", True
            except ValueError:
                kind, message = "invalid_json", "Некорректный JSON"
            except requests.RequestException as error:
                kind, message = "request_error", type(error).__name__
            events.append(self.event(url, kind, message, attempt + 1))
            if not retryable:
                return None
            if attempt == self.retries:
                self.cooldowns[host] = time.monotonic() + 30
                return None
            time.sleep(min(2 ** attempt, 30))
        return None

    def event(self, url, kind, message, attempt=0):
        if self.bulk_key:
            message = message.replace(self.bulk_key, "[redacted]")
        return {"at": utc_now(), "url": url, "type": kind, "message": message, "attempt": attempt}

    def prepare_batch(self, addresses):
        """IPWHOIS Pro supports at most 100 IPs per HTTPS POST request."""
        self.bulk_records, self.bulk_events = {}, []
        self.bulk_attempted = {ip for ip in addresses if ipaddress.ip_address(ip).is_global
                               and not ipaddress.ip_address(ip).is_multicast}
        if not self.bulk_key or not self.bulk_attempted:
            self.bulk_attempted.clear()
            return
        if len(self.bulk_attempted) > 100:
            raise ValueError("Максимум 100 IP в bulk-запросе")
        url = "https://ipwhois.pro/bulk"
        data = self.fetch(url, self.bulk_events, [ip for ip in addresses if ip in self.bulk_attempted])
        rows = data if isinstance(data, list) else data.get("data", []) if isinstance(data, dict) else []
        if not isinstance(rows, list):
            rows = []
        seen = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            try:
                ip = str(ipaddress.ip_address(row.get("ip")))
            except (ValueError, TypeError):
                continue
            if ip not in self.bulk_attempted:
                continue
            if ip in seen:
                self.bulk_records.pop(ip, None)
                continue
            seen.add(ip)
            if row.get("success") is False or row.get("error"):
                continue
            connection = row.get("connection") if isinstance(row.get("connection"), dict) else {}
            zone = row.get("timezone") if isinstance(row.get("timezone"), dict) else {}
            parsed = {field: clean(row.get(field)) for field in GEO_FIELDS}
            parsed.update(organization=clean(connection.get("org")), asn=clean(connection.get("asn")),
                          isp=clean(connection.get("isp")), postal_code=clean(row.get("postal")),
                          timezone=clean(zone.get("id")))
            parsed["asn"] = normalize_asn(parsed["asn"])
            if any(parsed[k] != MISSING for k in ("organization", "country", "asn", "isp")):
                self.bulk_records[ip] = parsed

    def lookup(self, ip):
        address = ipaddress.ip_address(ip)
        result = {field: MISSING for field in (*GEO_FIELDS, *NETWORK_FIELDS, "asn_description")}
        result.update(ip=str(address), success="No", request_status="failed", error_type="no_data",
                      error_message="", completeness="failed", missing_fields=list(GEO_FIELDS),
                      data_source=MISSING, source_url=MISSING, retrieved_at=utc_now(),
                      field_sources={}, source_details={}, events=[], rdap_status="disabled",
                      cache_hit=False, resumed=False)
        events = result["events"]
        if not address.is_global or address.is_multicast:
            result.update(request_status="skipped", completeness="skipped", error_type="non_public_ip",
                          error_message="Локальный/служебный адрес; запросы не отправлялись")
            return result
        bulk = self.bulk_records.get(str(address))
        if str(address) in self.bulk_attempted:
            events.extend(self.bulk_events)
            if bulk is None:
                events.append(self.event("https://ipwhois.pro/bulk", "bulk_no_data", "Нет подтверждённых данных для IP; использован резервный источник"))
        if bulk is not None:
            result.update(bulk)
            self.sources(result, bulk, "ipwhois-pro", "https://ipwhois.pro/bulk")
        for name in (() if bulk is not None else self.providers):
            template, mapping = PROVIDERS[name]
            url = template.format(ip=address)
            data = self.fetch(url, events)
            if data is None:
                continue
            if data.get("error") or data.get("reserved") or data.get("success") is False:
                events.append(self.event(url, "api_error", clean(data.get("reason") or data.get("message") or "API отклонил запрос")))
                continue
            returned_ip = data.get("ip")
            if returned_ip is not None:
                try:
                    if ipaddress.ip_address(returned_ip) != address:
                        raise ValueError("IP mismatch")
                except ValueError:
                    events.append(self.event(url, "ip_mismatch", "API вернул другой IP"))
                    continue
            parsed = {field: clean(data.get(mapping.get(field, field))) for field in GEO_FIELDS}
            parsed["asn"] = normalize_asn(parsed["asn"])
            if any(parsed[k] != MISSING for k in ("organization", "country", "asn", "isp")):
                result.update(parsed)
                self.sources(result, parsed, name, url)
                break
            events.append(self.event(url, "no_data", "Нет географических или сетевых данных"))
        if self.rdap:
            self.enrich_rdap(address, result)
        present = bool(result["field_sources"])
        expected = (*GEO_FIELDS, *NETWORK_FIELDS) if self.rdap else GEO_FIELDS
        missing = [field for field in expected if result[field] == MISSING]
        result.update(retrieved_at=utc_now(), missing_fields=missing, completeness=("full" if not missing else "partial") if present else "failed",
                      success="Yes" if present else "No", request_status="HTTP 200" if present else "failed",
                      data_source=", ".join(result["source_details"]) or MISSING,
                      source_url=", ".join(s["url"] for s in result["source_details"].values()) or MISSING,
                      error_type="" if present else (events[-1]["type"] if events else "no_data"),
                      error_message="; ".join(f"{urlsplit(e['url']).hostname}: {e['message']}" for e in events))
        return result

    @staticmethod
    def sources(result, parsed, name, url):
        for field, value in parsed.items():
            if value != MISSING:
                result["field_sources"][field] = name
        result["source_details"][name] = {"url": url, "retrieved_at": utc_now()}

    def enrich_rdap(self, address, result):
        events = result["events"]
        family = f"ipv{address.version}"
        bootstrap_url = f"https://data.iana.org/rdap/{family}.json"
        if family not in self.bootstrap:
            data = self.fetch(bootstrap_url, events)
            if data is not None:
                self.bootstrap[family] = data
        bootstrap = self.bootstrap.get(family, {})
        candidates = []
        try:
            for networks, urls in bootstrap.get("services", []):
                for network in networks:
                    prefix = ipaddress.ip_network(network)
                    if address in prefix:
                        candidates.extend((prefix.prefixlen, url) for url in urls if url.startswith("https://"))
        except (ValueError, TypeError, AttributeError):
            events.append(self.event(bootstrap_url, "rdap_bootstrap_error", "Некорректный IANA bootstrap"))
        if not candidates:
            result["rdap_status"] = "failed"
            events.append(self.event(bootstrap_url, "rdap_unavailable", "Не найден HTTPS-сервер RDAP"))
            return
        _, base = max(candidates, key=lambda item: item[0])
        url = f"{base.rstrip('/')}/ip/{address}"
        data = self.fetch(url, events, follow_rdap=True)
        if data is None:
            result["rdap_status"] = "failed"
            return
        try:
            start, end = ipaddress.ip_address(data["startAddress"]), ipaddress.ip_address(data["endAddress"])
            if start.version != address.version or end.version != address.version or not start <= address <= end:
                raise ValueError("RDAP range mismatch")
        except (KeyError, ValueError, TypeError):
            result["rdap_status"] = "failed"
            events.append(self.event(url, "rdap_invalid_response", "RDAP не подтвердил диапазон адреса"))
            return
        registrants = []
        for entity in data.get("entities", []) if isinstance(data.get("entities"), list) else []:
            if not isinstance(entity, dict) or "registrant" not in (entity.get("roles") or []):
                continue
            card = entity.get("vcardArray")
            if isinstance(card, list) and len(card) == 2 and isinstance(card[1], list):
                for entry in card[1]:
                    if isinstance(entry, list) and len(entry) >= 4 and entry[0] in ("fn", "org"):
                        value = clean(entry[3])
                        if value != MISSING:
                            registrants.append(value)
        parsed = dict(netname=clean(data.get("name")), network_start=str(start), network_end=str(end),
                      network_handle=clean(data.get("handle")), registration_country=clean(data.get("country")),
                      registered_organization=", ".join(dict.fromkeys(registrants)) or MISSING)
        result.update(parsed, rdap_status="success")
        self.sources(result, parsed, "rdap", self.final_urls.get(url, url))
