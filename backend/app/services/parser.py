import re

def parse_nmap_output(output: str):
    results = []

    lines = output.split("\n")

    for line in lines:
        match = re.match(r"(\d+)/tcp\s+(\w+)\s+([\w\-]+)", line)

        if match:
            results.append({
                "port": int(match.group(1)),
                "state": match.group(2),
                "service": match.group(3)
            })

    return results
