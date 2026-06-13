def score_findings(findings):

    scored = []

    for finding in findings:

        severity = "low"

        text = finding.lower()

        if "sql" in text:
            severity = "critical"

        elif "phpmyadmin" in text:
            severity = "high"

        elif "source code" in text:
            severity = "high"

        elif "directory indexing" in text:
            severity = "medium"

        elif "x-frame-options" in text:
            severity = "medium"

        elif "httponly" in text:
            severity = "medium"

        elif "server leaks" in text:
            severity = "low"

        elif "apache default" in text:
            severity = "low"

        scored.append({
            "finding": finding,
            "severity": severity
        })

    return scored
