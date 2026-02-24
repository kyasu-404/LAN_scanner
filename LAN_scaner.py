import nmap
import csv
import json
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress

console = Console()
DEFAULT_THREADS = 100


# ================== UI ==================

def banner():
    console.print(Panel.fit(
        "[bold cyan]LAN SCANNER[/bold cyan]",
        border_style="cyan"
    ))


# ================== CONFIG ==================

def get_config():
    network = Prompt.ask("Подсеть", default="192.168.1.0/24")

    console.print("\n[bold]Режим:[/bold]")
    console.print("1 - FAST")
    console.print("2 - BALANCED")
    console.print("3 - FULL")

    mode = Prompt.ask("Выбор", choices=["1", "2", "3"], default="2")

    threads = int(Prompt.ask("Потоки", default=str(DEFAULT_THREADS)))
    detect_os = Confirm.ask("Определять ОС?", default=False)
    custom_ports = Prompt.ask("Свои порты (Enter = нет)", default="")

    console.print("\nВывод:")
    console.print("1 - Терминал")
    console.print("2 - CSV")
    console.print("3 - JSON")
    console.print("4 - HTML")

    output = Prompt.ask("Выбор", choices=["1", "2", "3", "4"], default="1")
    deep_scan = Confirm.ask("Deep scan одного IP?", default=False)

    return network, mode, threads, detect_os, custom_ports, output, deep_scan


# ================== ARGUMENTS ==================

def build_args(mode, detect_os, custom_ports):
    args = "-sS -T4 -sV"

    if custom_ports:
        args += f" -p {custom_ports}"
    else:
        if mode == "1":
            args += " -F"
        elif mode == "2":
            args += " --top-ports 1000"
        elif mode == "3":
            args += " -p-"

    if detect_os:
        args += " -O"

    return args


# ================== DISCOVERY ==================

def arp_discovery(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments="-sn -PR")
    return [h for h in nm.all_hosts() if nm[h].state() == "up"]


# ================== SMART CLASSIFICATION ==================

def classify_device(result, vendor):
    ports = {p["port"] for p in result["ports"]}
    os_name = result["os"].lower()
    score = 0
    device = "Unknown"

    if 9100 in ports or 515 in ports or 631 in ports:
        device = "Printer"
        score += 80

    elif 8291 in ports or "mikrotik" in os_name:
        device = "Router (MikroTik)"
        score += 85

    elif 554 in ports:
        device = "IP Camera"
        score += 75

    elif 5000 in ports or 5001 in ports:
        device = "NAS"
        score += 75

    elif 3389 in ports and 445 in ports:
        device = "Windows PC"
        score += 85

    elif 22 in ports and 80 in ports:
        device = "Linux Server"
        score += 70

    if "hp" in vendor.lower() or "canon" in vendor.lower():
        device = "Printer"
        score += 15

    if score == 0:
        score = 40

    return device, min(score, 99)


# ================== SCAN ==================

def scan_host(host, args):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments=args)

    if host not in nm.all_hosts():
        return None

    data = nm[host]

    mac = data["addresses"].get("mac", "") if "addresses" in data else ""
    vendor = data.get("vendor", {})
    vendor_name = vendor.get(mac, "") if mac else ""

    result = {
        "ip": host,
        "hostname": data.hostname(),
        "os": "Unknown",
        "mac": mac,
        "vendor": vendor_name,
        "ports": []
    }

    if "osmatch" in data and data["osmatch"]:
        result["os"] = data["osmatch"][0]["name"]

    if "tcp" in data:
        for port in data["tcp"]:
            if data["tcp"][port]["state"] == "open":
                info = data["tcp"][port]
                result["ports"].append({
                    "port": port,
                    "service": info["name"],
                    "product": info.get("product", ""),
                    "version": info.get("version", "")
                })

    device, confidence = classify_device(result, vendor_name)
    result["device_type"] = device
    result["confidence"] = confidence

    return result


# ================== OUTPUT ==================

def sort_results(results):
    return sorted(results, key=lambda x: ipaddress.IPv4Address(x["ip"]))


def output_terminal(results):
    table = Table(title="Smart Scan Results")

    table.add_column("IP", style="cyan")
    table.add_column("Device", style="green")
    table.add_column("Confidence", style="yellow")
    table.add_column("OS", style="magenta")
    table.add_column("Vendor", style="blue")

    for r in results:
        table.add_row(
            r["ip"],
            r["device_type"],
            f"{r['confidence']}%",
            r["os"],
            r["vendor"]
        )

    console.print(table)


def output_csv(results):
    with open("scan_results.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Device", "Confidence", "OS", "Vendor"])

        for r in results:
            writer.writerow([
                r["ip"],
                r["device_type"],
                r["confidence"],
                r["os"],
                r["vendor"]
            ])
    console.print("[green]CSV сохранён[/green]")


def output_json(results):
    with open("scan_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
    console.print("[green]JSON сохранён[/green]")


def output_html(results):
    html = "<html><body><h1>Smart Scan Results</h1><table border='1'>"
    html += "<tr><th>IP</th><th>Device</th><th>Confidence</th><th>OS</th><th>Vendor</th></tr>"

    for r in results:
        html += f"<tr><td>{r['ip']}</td><td>{r['device_type']}</td><td>{r['confidence']}%</td><td>{r['os']}</td><td>{r['vendor']}</td></tr>"

    html += "</table></body></html>"

    with open("scan_results.html", "w", encoding="utf-8") as f:
        f.write(html)

    console.print("[green]HTML сохранён[/green]")


# ================== MAIN ==================

def main():
    banner()
    network, mode, threads, detect_os, custom_ports, output_type, deep_scan = get_config()
    args = build_args(mode, detect_os, custom_ports)

    console.print("\n[bold yellow]ARP discovery...[/bold yellow]")
    live_hosts = arp_discovery(network)

    if not live_hosts:
        console.print("[red]Хосты не найдены[/red]")
        return

    results = []

    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=len(live_hosts))

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_host, h, args): h for h in live_hosts}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                progress.advance(task)

    results = sort_results(results)

    if output_type == "1":
        output_terminal(results)
    elif output_type == "2":
        output_csv(results)
    elif output_type == "3":
        output_json(results)
    elif output_type == "4":
        output_html(results)

    if deep_scan:
        ip = Prompt.ask("IP для deep scan")
        deep_result = scan_host(ip, "-sS -T4 -sV -O -p-")
        output_terminal([deep_result])

    console.print("\n[bold cyan]Готово[/bold cyan]")


if __name__ == "__main__":
    main()