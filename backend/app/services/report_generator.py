from app.services.job_manager import get_job


def calculate_overall_risk(risk_analysis):

    severities = [f["severity"] for f in risk_analysis]

    if "critical" in severities:
        return "Critical"
    elif "high" in severities:
        return "High"
    elif "medium" in severities:
        return "Medium"
    elif "low" in severities:
        return "Low"
    else:
        return "Informational"


def calculate_risk_score(risk_analysis):

    score = 0

    for finding in risk_analysis:

        severity = finding["severity"].lower()

        if severity == "critical":
            score += 30
        elif severity == "high":
            score += 20
        elif severity == "medium":
            score += 10
        elif severity == "low":
            score += 5
        elif severity == "info":
            score += 1

    return min(score, 100)


def generate_recommendations(risk_analysis):

    recommendations = set()

    for item in risk_analysis:

        finding = item["finding"].lower()

        if "directory indexing" in finding:
            recommendations.add("Disable directory listing")

        elif "x-frame-options" in finding:
            recommendations.add("Implement X-Frame-Options header")

        elif "phpmyadmin" in finding:
            recommendations.add(
                "Restrict or secure exposed phpMyAdmin interfaces"
            )

        elif "source code exposure" in finding:
            recommendations.add(
                "Review potential source code exposure risks"
            )

        elif "httponly" in finding:
            recommendations.add(
                "Set HttpOnly flag on cookies"
            )

        elif "sql injection" in finding:
            recommendations.add(
                "Immediately remediate SQL injection vulnerabilities"
            )

        elif "anonymous ftp" in finding:
            recommendations.add(
                "Disable anonymous FTP access"
            )

        elif "ftp banner" in finding:
            recommendations.add(
                "Reduce FTP banner information disclosure"
            )

        elif "weak ssh" in finding:
            recommendations.add(
                "Review SSH algorithms and disable weak ciphers"
            )

        elif "legacy ssh rsa" in finding:
            recommendations.add(
                "Disable legacy SSH RSA algorithms where possible"
            )

        elif "ssh banner" in finding:
            recommendations.add(
                "Reduce SSH banner information disclosure"
            )

        elif "smbv1" in finding:
            recommendations.add(
                "Disable SMBv1 and enforce modern SMB protocols"
            )

        elif "smb signing" in finding:
            recommendations.add(
                "Enforce SMB message signing"
            )

        elif "administrative smb shares" in finding:
            recommendations.add(
                "Restrict administrative SMB share exposure"
            )

        elif "mysql service" in finding:
            recommendations.add(
                "Restrict remote MySQL service exposure"
            )

        elif "mysql authentication" in finding:
            recommendations.add(
                "Review MySQL authentication configuration"
            )

    return sorted(list(recommendations))


def generate_report(job_id):

    job = get_job(job_id)

    if not job:
        return {"error": "Job not found"}

    ports = [
        port for port in job.get("results", {}).get("parsed", [])
        if port.get("state") == "open"
    ]

    findings = set()
    risk_analysis = {}

    for followup in job.get("followup_results", []):

        # WEB
        nikto_data = followup.get("nikto", {})

        for finding in nikto_data.get("findings", []):
            findings.add(finding)

        for item in nikto_data.get("risk_analysis", []):
            risk_analysis[item["finding"]] = item

        for tech in followup.get("whatweb", []):

            fingerprint = tech.get("fingerprint", "")

            if fingerprint:
                findings.add(
                    f"Web fingerprint: {fingerprint}"
                )

        for vuln in followup.get("nuclei", []):

            template_id = vuln.get("template-id", "unknown")
            info = vuln.get("info", {})
            severity = info.get("severity", "info")

            findings.add(
                f"Nuclei: {template_id} ({severity})"
            )

            risk_analysis[template_id] = {
                "finding": f"Nuclei: {template_id}",
                "severity": severity
            }

        for entry in followup.get("gobuster", []):

            result = entry.get("result", "")

            if result:
                findings.add(
                    f"Gobuster: {result}"
                )

                risk_analysis[result] = {
                    "finding": f"Gobuster: {result}",
                    "severity": "low"
                }

        # SQLMAP
        sqlmap_data = followup.get("sqlmap", {})
        raw_output = sqlmap_data.get("raw_output", "")

        if raw_output:

            findings.add("SQLMap scan executed")

            if "is vulnerable" in raw_output.lower():

                findings.add(
                    "SQL injection vulnerability detected"
                )

                risk_analysis["sql_injection"] = {
                    "finding": "SQL injection vulnerability detected",
                    "severity": "critical"
                }

        # SERVICE MODULES
        for key, module_data in followup.items():

            # FTP
            if key.startswith("ftp_"):

                raw = module_data.get("raw_output", "")
                raw_lower = raw.lower()

                if "proftpd" in raw_lower:

                    findings.add(
                        "FTP service detected: ProFTPD"
                    )

                    risk_analysis["ftp_proftpd"] = {
                        "finding": "FTP service detected: ProFTPD",
                        "severity": "info"
                    }

                elif "vsftpd" in raw_lower:

                    findings.add(
                        "FTP service detected: vsFTPd"
                    )

                    risk_analysis["ftp_vsftpd"] = {
                        "finding": "FTP service detected: vsFTPd",
                        "severity": "info"
                    }

                if "anonymous ftp login allowed" in raw_lower:

                    findings.add(
                        "Anonymous FTP login allowed"
                    )

                    risk_analysis["ftp_anon"] = {
                        "finding": "Anonymous FTP login allowed",
                        "severity": "high"
                    }

                if "banner:" in raw:

                    findings.add(
                        "FTP banner disclosure detected"
                    )

                    risk_analysis["ftp_banner"] = {
                        "finding": "FTP banner disclosure detected",
                        "severity": "low"
                    }

            # SSH
            elif key.startswith("ssh_"):

                raw = module_data.get("raw_output", "")
                raw_lower = raw.lower()

                if "openssh" in raw_lower:

                    findings.add(
                        "SSH service detected: OpenSSH"
                    )

                    risk_analysis["ssh_service"] = {
                        "finding": "SSH service detected: OpenSSH",
                        "severity": "info"
                    }

                if "ssh2-enum-algos" in raw_lower:

                    findings.add(
                        "SSH algorithms enumerated"
                    )

                    risk_analysis["ssh_algos"] = {
                        "finding": "SSH algorithms enumerated",
                        "severity": "info"
                    }

                if "diffie-hellman-group1-sha1" in raw_lower:

                    findings.add(
                        "Weak SSH key exchange algorithm detected"
                    )

                    risk_analysis["ssh_weak_kex"] = {
                        "finding": "Weak SSH key exchange algorithm detected",
                        "severity": "medium"
                    }

                if "ssh-rsa" in raw_lower:

                    findings.add(
                        "Legacy SSH RSA algorithm detected"
                    )

                    risk_analysis["ssh_legacy_rsa"] = {
                        "finding": "Legacy SSH RSA algorithm detected",
                        "severity": "low"
                    }

                if "banner:" in raw:

                    findings.add(
                        "SSH banner disclosure detected"
                    )

                    risk_analysis["ssh_banner"] = {
                        "finding": "SSH banner disclosure detected",
                        "severity": "low"
                    }

            # SMB
            elif key.startswith("smb_"):

                raw = module_data.get("raw_output", "")
                raw_lower = raw.lower()

                if "smbv1" in raw_lower:

                    findings.add(
                        "SMBv1 protocol detected"
                    )

                    risk_analysis["smbv1"] = {
                        "finding": "SMBv1 protocol detected",
                        "severity": "high"
                    }

                if "message signing enabled but not required" in raw_lower:

                    findings.add(
                        "SMB signing not enforced"
                    )

                    risk_analysis["smb_signing"] = {
                        "finding": "SMB signing not enforced",
                        "severity": "medium"
                    }

                if "os discovery" in raw_lower:

                    findings.add(
                        "SMB OS discovery information exposed"
                    )

                    risk_analysis["smb_os"] = {
                        "finding": "SMB OS discovery information exposed",
                        "severity": "medium"
                    }

                if "ipc$" in raw_lower or "admin$" in raw_lower:

                    findings.add(
                        "Administrative SMB shares exposed"
                    )

                    risk_analysis["smb_admin_shares"] = {
                        "finding": "Administrative SMB shares exposed",
                        "severity": "medium"
                    }

                elif "disk" in raw_lower:

                    findings.add(
                        "SMB shares enumerated"
                    )

                    risk_analysis["smb_shares"] = {
                        "finding": "SMB shares enumerated",
                        "severity": "medium"
                    }

            # MYSQL
            elif key.startswith("mysql_"):

                raw = module_data.get("raw_output", "")
                raw_lower = raw.lower()

                if "mysql" in raw_lower:

                    findings.add(
                        "MySQL service detected"
                    )

                    risk_analysis["mysql_service"] = {
                        "finding": "MySQL service detected",
                        "severity": "info"
                    }

                if "protocol" in raw_lower:

                    findings.add(
                        "MySQL protocol information disclosed"
                    )

                    risk_analysis["mysql_protocol"] = {
                        "finding": "MySQL protocol information disclosed",
                        "severity": "low"
                    }

                if "empty password" in raw_lower:

                    findings.add(
                        "MySQL empty password vulnerability"
                    )

                    risk_analysis["mysql_empty_password"] = {
                        "finding": "MySQL empty password vulnerability",
                        "severity": "high"
                    }

                if "authentication" in raw_lower:

                    findings.add(
                        "MySQL authentication information exposed"
                    )

                    risk_analysis["mysql_auth_info"] = {
                        "finding": "MySQL authentication information exposed",
                        "severity": "low"
                    }

    findings = sorted(list(findings))
    risk_analysis = list(risk_analysis.values())

    return {
        "target": job.get("target"),
        "job_id": job_id,
        "status": job.get("status"),
        "ports": ports,
        "findings": findings,
        "recommendations": generate_recommendations(risk_analysis),
        "overall_risk": calculate_overall_risk(risk_analysis),
        "risk_score": calculate_risk_score(risk_analysis),
        "risk_analysis": risk_analysis,
        "ai_analysis": job.get("ai_analysis")
    }
