import csv
import html
import ipaddress
import json
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field, replace
from io import BytesIO
from pathlib import Path
from tempfile import NamedTemporaryFile

from rich.console import Console
from rich.progress import Progress
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text


console = Console()
DEFAULT_BATCH_SIZE = 32
MAX_BATCH_SIZE = 256
DISCOVERY_TIMEOUT = 120

PROFILES = {
    "1": ("FAST", ("-F",), 90),
    "2": ("BALANCED", ("--top-ports", "1000"), 180),
    "3": ("FULL", ("-p-",), 900),
}

REPORT_COLUMNS = (
    "IP", "Hostname", "MAC", "Vendor", "OS", "Device", "Evidence",
    "Status", "Detail", "TCP Port", "Service", "Product", "Version",
)


@dataclass
class Port:
    port: int
    service: str = ""
    product: str = ""
    version: str = ""


@dataclass
class Host:
    ip: str
    hostname: str = ""
    os: str = "Unknown"
    mac: str = ""
    vendor: str = ""
    ports: list[Port] = field(default_factory=list)
    device_type: str = "Unknown"
    evidence: list[str] = field(default_factory=list)
    status: str = "ok"
    detail: str = ""


@dataclass
class ScanRun:
    hosts: dict[str, Host] = field(default_factory=dict)
    error: str = ""
    warnings: str = ""
    timed_out: bool = False


def parse_ports(value):
    ports = []
    for part in value.split(","):
        match = re.fullmatch(r"([0-9]{1,5})(?:\s*-\s*([0-9]{1,5}))?", part.strip())
        if not match:
            raise ValueError("Введите номера или диапазоны через запятую, например 22,80,8000-8010.")
        first = int(match[1])
        last = int(match[2] or match[1])
        if not 1 <= first <= last <= 65535:
            raise ValueError("Допустимы порты от 1 до 65535 и диапазоны по возрастанию.")
        ports.append(str(first) if first == last else f"{first}-{last}")
    return ",".join(ports)


def parse_network(value):
    if "/" not in value:
        raise ValueError("Укажите IPv4-подсеть в CIDR, например 192.168.1.0/24.")
    return str(ipaddress.IPv4Network(value, strict=False))


def prompt_validated(label, default, parser):
    while True:
        value = Prompt.ask(label, default=default, show_default=bool(default)).strip()
        try:
            return parser(value)
        except ValueError as error:
            console.print(Text(str(error), style="red"))


def prompt_batch_size():
    while True:
        size = IntPrompt.ask("Адресов в группе", default=DEFAULT_BATCH_SIZE)
        if 1 <= size <= MAX_BATCH_SIZE:
            return size
        console.print(f"[red]Введите число от 1 до {MAX_BATCH_SIZE}.[/red]")


def find_nmap():
    path = shutil.which("nmap")
    if path is None:
        raise RuntimeError("Nmap не найден. Установите его и добавьте в PATH.")
    try:
        check = subprocess.run([path, "--version"], capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"Не удалось запустить Nmap: {error}") from error
    if check.returncode or not check.stdout.startswith(b"Nmap version "):
        message = decode_output(check.stderr) or decode_output(check.stdout)
        raise RuntimeError(message or "Команда nmap --version завершилась ошибкой.")
    return path


def can_detect_os():
    if "NMAP_UNPRIVILEGED" in os.environ:
        return False
    if "NMAP_PRIVILEGED" in os.environ:
        return True
    if os.name == "nt":
        from ctypes import windll

        return bool(windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def prompt_os_detection(default=False):
    if can_detect_os():
        return Confirm.ask("Определять ОС?", default=default)
    console.print("Определение ОС пропущено. Для него запустите сканер с правами Nmap для сырых пакетов.")
    return False


def scan_args(mode, custom_ports, detect_versions, detect_os):
    _, profile_ports, host_timeout = PROFILES[mode]
    args = ["--host-timeout", f"{host_timeout}s"]
    args.extend(("-p", custom_ports) if custom_ports else profile_ports)
    if detect_versions:
        args.append("-sV")
    if detect_os:
        args.append("-O")
    return args, host_timeout * 2 + 30


def decode_output(data):
    return (data or b"").decode("utf-8", errors="replace").strip()


def parse_host(element):
    address = element.find("address[@addrtype='ipv4']")
    if address is None:
        return None

    host = Host(str(ipaddress.IPv4Address(address.attrib["addr"])))
    hostname = element.find("hostnames/hostname")
    if hostname is not None:
        host.hostname = hostname.get("name", "")
    mac = element.find("address[@addrtype='mac']")
    if mac is not None:
        host.mac = mac.get("addr", "")
        host.vendor = mac.get("vendor", "")
    os_match = element.find("os/osmatch")
    if os_match is not None:
        host.os = os_match.get("name", "Unknown")

    for port in element.findall("ports/port[@protocol='tcp']"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            service = port.find("service")
            attributes = service.attrib if service is not None else {}
            host.ports.append(Port(
                int(port.attrib["portid"]),
                attributes.get("name", ""),
                attributes.get("product", ""),
                attributes.get("version", ""),
            ))

    state = element.find("status")
    if element.get("timedout") == "true":
        host.status, host.detail = "timeout", "Nmap превысил лимит времени для хоста."
    elif state is None or state.get("state") != "up":
        host.status, host.detail = "no_response", "Хост не подтвердил доступность."
    host.ports.sort(key=lambda port: port.port)
    return host


def parse_nmap(stdout):
    run = ScanRun()
    finished = None
    try:
        for _, element in ET.iterparse(BytesIO(stdout), events=("end",)):
            if element.tag == "host":
                host = parse_host(element)
                if host is not None:
                    run.hosts[host.ip] = host
                element.clear()
            elif element.tag == "finished":
                finished = element.attrib
    except (ET.ParseError, KeyError, ValueError) as error:
        run.error = f"Некорректный или неполный XML Nmap: {error}"
    if finished is not None and finished.get("exit") == "error":
        run.error = finished.get("errormsg") or "Nmap сообщил об ошибке."
    if finished is None and not run.error:
        run.error = "В XML Nmap отсутствует итог сканирования."
    return run


def run_nmap(path, args, targets, timeout):
    command = [path, "-oX", "-", *args, *targets]
    try:
        completed = subprocess.run(command, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        run = parse_nmap(error.output or b"")
        run.timed_out = True
        run.error = f"Nmap превысил лимит времени запуска ({timeout} с)."
        run.warnings = decode_output(error.stderr)
        return run
    except OSError as error:
        return ScanRun(error=f"Не удалось запустить Nmap: {error}")

    run = parse_nmap(completed.stdout)
    stderr = decode_output(completed.stderr)
    if completed.returncode:
        run.error = stderr or run.error or f"Nmap завершился с кодом {completed.returncode}."
    else:
        run.warnings = stderr
    return run


def classify_device(host):
    ports = {port.port for port in host.ports}
    products = " ".join(port.product for port in host.ports).casefold()
    os_name = host.os.casefold()
    candidates = {}

    if "mikrotik" in os_name or "mikrotik" in products:
        candidates["MikroTik"] = "MikroTik в отпечатке ОС или названии сервиса"
    if any(name in products for name in ("synology", "qnap", "diskstation")):
        candidates["NAS"] = "Продукт Synology, QNAP или DiskStation"
    if any(name in products for name in ("ip camera", "network camera")):
        candidates["IP Camera"] = "Сервис идентифицирован как IP-камера"
    if len(ports & {515, 631, 9100}) >= 2:
        candidates["Printer / Print server"] = "Открыто несколько портов печати"
    if "windows" in os_name:
        candidates["Windows host"] = "Windows в отпечатке ОС"
    elif {445, 3389} <= ports and host.os == "Unknown":
        candidates["Windows host"] = "Открыты TCP 445 и 3389"

    device = next(iter(candidates)) if len(candidates) == 1 else "Unknown"
    return device, list(candidates.values())


def collect_results(targets, run):
    results = []
    for original in targets:
        scanned = run.hosts.get(original.ip)
        if scanned is None:
            if run.error:
                status = "timeout" if run.timed_out else "error"
                results.append(replace(original, status=status, detail=run.error))
            else:
                results.append(replace(
                    original, status="no_response", detail="Nmap не вернул результат по адресу.",
                ))
            continue

        scanned.hostname = scanned.hostname or original.hostname
        if not scanned.mac:
            scanned.mac = original.mac
        if scanned.mac == original.mac and not scanned.vendor:
            scanned.vendor = original.vendor
        if run.error and scanned.status == "ok":
            scanned.status, scanned.detail = "partial", run.error
        scanned.device_type, scanned.evidence = classify_device(scanned)
        results.append(scanned)
    return results


def show_run_messages(run, stage):
    if run.error:
        console.print(Text(f"{stage} — {run.error}", style="red"))
    if run.warnings:
        console.print(Text(f"{stage} — {run.warnings}", style="yellow"))


def scan_network(path, network, batch_size, args, timeout):
    console.print("Обнаружение хостов…")
    discovery = run_nmap(path, ["-sn"], [network], DISCOVERY_TIMEOUT)
    show_run_messages(discovery, "Обнаружение")
    subnet = ipaddress.IPv4Network(network)
    live = [
        host for host in discovery.hosts.values()
        if host.status == "ok" and ipaddress.IPv4Address(host.ip) in subnet
    ]
    live.sort(key=lambda host: ipaddress.IPv4Address(host.ip))
    if not live:
        if not discovery.error:
            console.print("Отвечающие хосты не найдены.")
        return [], bool(discovery.error)

    console.print(f"Обнаружено хостов: {len(live)}")
    results = []
    with Progress(console=console) as progress:
        task = progress.add_task("Сканирование…", total=len(live))
        for offset in range(0, len(live), batch_size):
            group = live[offset:offset + batch_size]
            addresses = [host.ip for host in group]
            # Обычное обнаружение уже выполнили. Nmap может снова использовать ARP на том же L2.
            run = run_nmap(path, [*args, "-Pn"], addresses, timeout)
            show_run_messages(run, f"Группа {offset // batch_size + 1}")
            results.extend(collect_results(group, run))
            progress.advance(task, len(group))
    return results, bool(discovery.error)


def host_cells(host):
    return (
        host.ip, host.hostname, host.mac, host.vendor, host.os, host.device_type,
        ", ".join(host.evidence), host.status, host.detail,
    )


def report_rows(results):
    for host in results:
        common = host_cells(host)
        for port in host.ports:
            yield (*common, str(port.port), port.service, port.product, port.version)
        if not host.ports:
            yield (*common, "", "", "", "")


def output_terminal(results):
    hosts = Table(*REPORT_COLUMNS[:9], title="Хосты")
    services = Table("IP", *REPORT_COLUMNS[9:], title="Открытые TCP-порты")
    for host in results:
        hosts.add_row(*(Text(value) for value in host_cells(host)))
        for port in host.ports:
            services.add_row(*(Text(value) for value in (
                host.ip, str(port.port), port.service, port.product, port.version,
            )))
    console.print(hosts)
    if services.row_count:
        console.print(services)
    else:
        console.print("В результатах нет открытых TCP-портов.")


def spreadsheet_cell(value):
    if value.startswith(("\t", "\r", "\n")) or value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def write_html(stream, results):
    stream.write('<!doctype html>\n<html lang="ru"><head><meta charset="utf-8">\n')
    stream.write("<title>LAN Scanner</title>\n")
    stream.write("<style>table{border-collapse:collapse}th,td{border:1px solid gray;padding:.35rem}</style>\n")
    stream.write("</head><body><h1>LAN Scanner</h1><table>\n")
    stream.write("<thead><tr>" + "".join(f"<th>{column}</th>" for column in REPORT_COLUMNS))
    stream.write("</tr></thead><tbody>\n")
    for row in report_rows(results):
        cells = "".join(f"<td>{html.escape(value)}</td>" for value in row)
        stream.write(f"<tr>{cells}</tr>\n")
    stream.write("</tbody></table></body></html>\n")


def export_results(results, output, stem):
    path = Path(f"{stem}.{output}")
    temporary_path = None
    try:
        encoding = "utf-8-sig" if output == "csv" else "utf-8"
        with NamedTemporaryFile(
            mode="w", encoding=encoding, newline="", dir=path.parent, delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            if output == "csv":
                writer = csv.writer(stream)
                writer.writerow(REPORT_COLUMNS)
                writer.writerows(tuple(map(spreadsheet_cell, row)) for row in report_rows(results))
            elif output == "json":
                json.dump([asdict(host) for host in results], stream, ensure_ascii=False, indent=2)
                stream.write("\n")
            else:
                write_html(stream, results)
        temporary_path.replace(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return path


def show_report(results, stem):
    console.print("Вывод\n1 — терминал\n2 — CSV\n3 — JSON\n4 — HTML")
    choice = Prompt.ask("Формат", choices=["1", "2", "3", "4"], default="1")
    if choice == "1":
        output_terminal(results)
        return True

    formats = {"2": "csv", "3": "json", "4": "html"}
    try:
        path = export_results(results, formats[choice], stem)
    except OSError as error:
        console.print(Text(f"Не удалось сохранить отчёт: {error}", style="red"))
        return False
    console.print(Text(f"Отчёт сохранён: {path}"))
    return True


def deep_scan(path):
    ip = prompt_validated("IPv4 для Deep Scan", "", lambda value: str(ipaddress.IPv4Address(value)))
    args, timeout = scan_args("3", "", True, prompt_os_detection(default=True))
    run = run_nmap(path, args, [ip], timeout)
    show_run_messages(run, "Deep Scan")
    results = collect_results([Host(ip)], run)
    saved = show_report(results, "deep_scan_results")
    return saved and all(host.status == "ok" for host in results)


def main():
    console.print("[bold cyan]LAN Scanner[/bold cyan]")
    path = find_nmap()
    console.print("1 — сканирование подсети\n2 — Deep Scan одного IPv4")
    if Prompt.ask("Действие", choices=["1", "2"], default="1") == "2":
        return 0 if deep_scan(path) else 1

    network = prompt_validated("IPv4-подсеть", "192.168.1.0/24", parse_network)
    console.print("\n".join(f"{key} — {profile[0]}" for key, profile in PROFILES.items()))
    mode = Prompt.ask("Профиль", choices=PROFILES.keys(), default="2")
    ports = prompt_validated(
        "Свои TCP-порты (Enter — по профилю)", "", lambda value: parse_ports(value) if value else "",
    )
    detect_versions = Confirm.ask("Определять версии сервисов?", default=mode != "1")
    args, timeout = scan_args(mode, ports, detect_versions, prompt_os_detection())
    results, discovery_failed = scan_network(path, network, prompt_batch_size(), args, timeout)
    success = not discovery_failed
    if results:
        saved = show_report(results, "scan_results")
        success = success and saved and all(host.status == "ok" for host in results)
    if Confirm.ask("Запустить Deep Scan одного IPv4?", default=False):
        success = deep_scan(path) and success
    return 0 if success else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        console.print(Text(str(error), style="red"))
        raise SystemExit(1) from None
    except (KeyboardInterrupt, EOFError):
        console.print("\nСканирование прервано.")
        raise SystemExit(130) from None
