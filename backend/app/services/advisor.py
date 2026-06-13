def analyze_findings(parsed_ports):

    recommendations = []

    for port in parsed_ports:

        p = port["port"]

        if p in [80,443,3000,8080]:

            recommendations.append({
                "action":"web_scan",
                "message":"Web service detected. Launch web vulnerability scan?",
                "approved": False
            })

        if p == 22:

            recommendations.append({
                "action":"ssh_review",
                "message":"SSH exposed. Review access controls.",
                "approved": False
            })

    return recommendations
