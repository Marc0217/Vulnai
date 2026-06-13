import ollama

from app.services.job_manager import (
    get_job,
    save_chat_message,
    get_chat_history
)


def ask_ai_about_report(job_id, question):

    job = get_job(job_id)

    if not job:
        return "Job not found."

    findings = set()
    severity_summary = []

    for followup in job.get("followup_results", []):

        for finding in followup.get("findings", []):
            findings.add(finding)

        for item in followup.get("risk_analysis", []):
            severity_summary.append(
                f"{item['finding']} ({item['severity']})"
            )

    findings = sorted(list(findings))
    severity_summary = sorted(list(set(severity_summary)))

    system_prompt = f"""
You are an AI cybersecurity analyst assistant.

Context:
Target: {job['target']}
Findings: {findings}
Severity Summary: {severity_summary}

Rules:
- Be concise.
- Be technically accurate.
- Base answers only on the provided context.
- Do not invent vulnerabilities.
- Give actionable cybersecurity guidance.
"""

    chat_history = get_chat_history(job_id)

    # SOLO últimas 6 interacciones
    recent_history = chat_history[-6:]

    messages = [
        {
            "role": "system",
            "content": system_prompt
        }
    ]

    messages.extend(recent_history)

    messages.append({
        "role": "user",
        "content": question
    })

    try:
        response = ollama.chat(
            model="phi3:mini",
            messages=messages
        )

        answer = response["message"]["content"]

        save_chat_message(job_id, "user", question)
        save_chat_message(job_id, "assistant", answer)

        return answer

    except Exception as e:
        return f"AI assistant unavailable: {str(e)}"
