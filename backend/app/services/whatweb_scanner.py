import subprocess
import re


def clean_ansi(text):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)


def run_whatweb_scan(target, ports):

    technologies = []

    for port in ports:

        url = f"http://{target}:{port}"

        result = subprocess.run(
            ["whatweb", "--no-errors", "--color=never", url],
            capture_output=True,
            text=True,
	    timeout=90
        )

        output = clean_ansi(result.stdout.strip())

        if output:
            technologies.append({
                "port": port,
                "fingerprint": output
            })

    return technologies
