import subprocess
import json

NUCLEI_PATH = "/home/usuario/go/bin/nuclei"


def run_nuclei_scan(target, ports):

    findings = []

    for port in ports:

        url = f"http://{target}:{port}"

        result = subprocess.run(
            [
                NUCLEI_PATH,
                "-u",
                url,
                "-json",
                "-silent"
            ],
            capture_output=True,
            text=True,
	    timeout=45
        )

        for line in result.stdout.splitlines():

            try:
                findings.append(json.loads(line))

            except:
                continue

    return findings
