import subprocess


def run_sqlmap_scan(url):

    result = subprocess.run(
        [
            "sqlmap",
            "-u",
            url,
            "--batch",
            "--answers=follow=Y,continue=Y,reduce=Y",
            "--flush-session",
            "--random-agent",
            "--level=1",
            "--risk=1"
        ],
        capture_output=True,
        text=True,
        timeout=120
    )

    return {
        "target_url": url,
        "raw_output": result.stdout
    }
