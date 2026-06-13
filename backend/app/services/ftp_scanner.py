import subprocess


def run_ftp_scan(target, port):

    result = subprocess.run(
        [
            "nmap",
            "--script",
            "ftp-anon,ftp-syst,banner",
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
