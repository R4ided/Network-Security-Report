import subprocess
import sys
from pathlib import Path

if len(sys.argv) != 2:
    print("Usage: python scanner.py TARGET")
    sys.exit(1)

target = sys.argv[1]
output = Path("sample-nmap-output.txt")

try:
    result = subprocess.run(
        ["nmap", "-sV", target],
        capture_output=True,
        text=True,
        check=True
    )

    output.write_text(result.stdout, encoding="utf-8")
    print(result.stdout)
    print(f"\nSaved results to {output}")

except FileNotFoundError:
    print("Error: Nmap is not installed or is not in PATH.")
    sys.exit(1)

except subprocess.CalledProcessError as e:
    print("Nmap failed:")
    print(e.stderr)
    sys.exit(1)