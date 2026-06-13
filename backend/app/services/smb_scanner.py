import subprocess


def run_smb_scan(target, port):

    result = subprocess.run(
        [
            "nmap",
            "--script",
            "smb-os-discovery,smb-protocols,smb-enum-shares",
            "-p",
            str(port),
            target
        ],
        capture_output=True,
        text=True,
        timeout=90
    )

    return {
        "port": port,
        "raw_output": result.stdout
    }
