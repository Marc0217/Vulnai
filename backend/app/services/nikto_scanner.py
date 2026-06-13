import subprocess

from app.services.nikto_parser import parse_nikto_output
from app.services.risk_engine import score_findings


def run_nikto_scan(target, ports):

    all_findings = []
    all_risk_analysis = []
    all_raw_output = ""

    for port in ports:

        result = subprocess.run(
            ["nikto", "-h", target, "-p", str(port)],
            capture_output=True,
            text=True,
	    timeout=90
        )

        raw_output = result.stdout

        findings = parse_nikto_output(raw_output)

        risk_scored = score_findings(findings)

        all_raw_output += raw_output + "\n"
        all_findings.extend(findings)
        all_risk_analysis.extend(risk_scored)

    return {
        "raw": all_raw_output,
        "findings": all_findings,
        "risk_analysis": all_risk_analysis
    }
