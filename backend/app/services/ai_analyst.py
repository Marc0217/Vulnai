import ollama
import json


def analyze_security_findings(report_data):

    prompt = f"""
You are a senior cybersecurity analyst specializing in vulnerability assessment.

Analyze the provided vulnerability report.

Return ONLY valid JSON in this exact format:

{{
  "executive_summary": "concise executive overview",
  "threat_assessment": "technical threat explanation",
  "priority_actions": [
    "specific remediation action 1",
    "specific remediation action 2"
  ],
  "next_actions": [
    "recommended follow-up assessment 1",
    "recommended follow-up assessment 2"
  ]
}}

Rules:
- Be specific and technically actionable.
- Do NOT provide generic advice.
- Base recommendations ONLY on the findings provided.
- Mention relevant exposed technologies if applicable.
- Suggest realistic next security validation steps.
- Do not invent vulnerabilities not present in the findings.

Target:
{report_data['target']}

Open Ports:
{report_data['ports']}

Findings:
{report_data['findings']}

Risk Analysis:
{report_data['risk_analysis']}

Return JSON only.
"""

    try:
        response = ollama.chat(
            model="mistral",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        content = response["message"]["content"]

        try:
            return json.loads(content)

        except Exception:
            return {
                "executive_summary": "AI response parsing failed.",
                "threat_assessment": content,
                "priority_actions": [],
                "next_actions": []
            }

    except Exception as e:
        return {
            "executive_summary": "AI analysis unavailable.",
            "threat_assessment": str(e),
            "priority_actions": [],
            "next_actions": []
        }
