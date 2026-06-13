import subprocess

from app.services.parser import parse_nmap_output
from app.services.advisor import analyze_findings


def run_nmap_scan(target: str):

    result = subprocess.run(
        ["nmap", target],
        capture_output=True,
        text=True
    )

    raw_output = result.stdout

    parsed_results = parse_nmap_output(raw_output)

    advice = analyze_findings(parsed_results)

    return {
        "raw": raw_output,
        "parsed": parsed_results,
        "advice": advice
    }
