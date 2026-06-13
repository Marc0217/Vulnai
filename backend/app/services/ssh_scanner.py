import subprocess


def run_ssh_scan(target, port):

    result = subprocess.run(
        [
            "nmap",
            "--script",
            "ssh2-enum-algos,banner",
            "-p",
            str(port),
            target
        ],
        capture_output=True,
        text=True,
        timeout=60
    )

    return {
        "port": port,
        "raw_output": result.stdout
    }
