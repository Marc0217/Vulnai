import subprocess


WORDLIST = "/usr/share/dirb/wordlists/others/best110.txt"


def run_gobuster_scan(target, ports):

    findings = []

    for port in ports:

        url = f"http://{target}:{port}"

        result = subprocess.run(
            [
                "gobuster",
                "dir",
                "-u",
                url,
                "-w",
                WORDLIST,
                "-q"
            ],
            capture_output=True,
            text=True,
	    timeout=45
        )

        for line in result.stdout.splitlines():

            if line.strip():
                findings.append({
                    "port": port,
                    "result": line.strip()
                })

    return findings
