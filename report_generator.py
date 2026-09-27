import re
from pathlib import Path

INPUT = Path("sample-nmap-output.txt")
OUTPUT = Path("example-report.html")

REVIEW_PORTS = {
    3389: "RDP exposed",
    22: "SSH detected",
}

def parse_results(text):
    host = "Unknown"
    ports = []

    match = re.search(r"Nmap scan report for (.+)", text)
    if match:
        host = match.group(1).strip()

    for line in text.splitlines():
        match = re.match(
            r"^(\d+)/tcp\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?$",
            line
        )

        if not match:
            continue

        port = int(match.group(1))
        state = match.group(2)
        service = match.group(3)

        if state == "open":
            ports.append({
                "port": port,
                "protocol": "tcp",
                "state": state,
                "service": service,
                "flag": REVIEW_PORTS.get(port)
            })

    return host, ports


def make_report(host, ports):
    lines = [
        "Network Security Report",
        "-----------------------",
        f"Host: {host}",
        ""
    ]

    for item in ports:
        line = (
            f"{item['port']}/{item['protocol']} "
            f"{item['state'].upper()} "
            f"{item['service'].upper()}"
        )

        if item["flag"]:
            line += " [REVIEW]"

        lines.append(line)

    lines.extend(["", "Flags:", ""])

    for item in ports:
        if item["flag"]:
            lines.append(f"[!] {item['flag']}")

    return "\n".join(lines)


def make_html(report):
    report = (
        report
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Network Security Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 40px;
}}
pre {{
    background: #f4f4f4;
    padding: 20px;
    border-radius: 8px;
}}
</style>
</head>
<body>
<h1>Network Security Report</h1>
<pre>{report}</pre>
</body>
</html>
"""


if not INPUT.exists():
    print("Error: sample-nmap-output.txt was not found.")
    print("Create the sample file or run scanner.py first.")
    raise SystemExit(1)

text = INPUT.read_text(encoding="utf-8")
host, ports = parse_results(text)

report = make_report(host, ports)
OUTPUT.write_text(make_html(report), encoding="utf-8")

print(report)
print(f"\nHTML report saved to {OUTPUT}")