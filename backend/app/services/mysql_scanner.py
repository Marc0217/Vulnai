import subprocess


def run_mysql_scan(target, port):

    result = subprocess.run(
        [
            "nmap",
            "--script",
            "mysql-info,mysql-empty-password",
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
