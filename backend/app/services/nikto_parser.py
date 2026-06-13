def parse_nikto_output(output):

    findings = set()

    for line in output.split("\n"):

        line = line.strip()

        if not line.startswith("+"):
            continue

        line_lower = line.lower()

        if "target ip" in line_lower:
            continue
        if "target hostname" in line_lower:
            continue
        if "target port" in line_lower:
            continue
        if "start time" in line_lower:
            continue
        if "end time" in line_lower:
            continue
        if "items checked" in line_lower:
            continue
        if "host(s) tested" in line_lower:
            continue
        if "server:" in line_lower:
            continue
        if "allowed http methods" in line_lower:
            continue
        if "retrieved x-powered-by" in line_lower:
            continue
        if "no cgi directories" in line_lower:
            continue

        if "directory indexing" in line_lower:
            findings.add("Directory indexing detected")
            continue

        if "x-frame-options" in line_lower:
            findings.add("Missing X-Frame-Options header")
            continue

        if "httponly" in line_lower:
            findings.add("Cookie missing HttpOnly flag")
            continue

        if "phpmyadmin" in line_lower:
            findings.add("Exposed phpMyAdmin interface")
            continue

        if "server leaks inodes" in line_lower:
            findings.add("ETag inode information leakage")
            continue

        if "apache default file" in line_lower:
            findings.add("Apache default files exposed")
            continue

        if "weblogic allows source code" in line_lower:
            findings.add("Potential source code exposure")
            continue

    return sorted(list(set(findings)))
