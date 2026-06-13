from io import BytesIO
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf_report(report_data):

    buffer = BytesIO()

    doc = SimpleDocTemplate(buffer)

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph("VulnAI Security Assessment Report", styles["Title"])
    )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(f"Target: {report_data['target']}", styles["Normal"])
    )

    content.append(
        Paragraph(f"Job ID: {report_data['job_id']}", styles["Normal"])
    )

    content.append(
        Paragraph(f"Status: {report_data['status']}", styles["Normal"])
    )

    content.append(
        Paragraph(
            f"Overall Risk: {report_data['overall_risk']}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"Risk Score: {report_data['risk_score']}/100",
            styles["Normal"]
        )
    )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph("Findings", styles["Heading2"])
    )

    for finding in report_data["findings"]:
        content.append(
            Paragraph(str(finding), styles["Normal"])
        )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph("Recommendations", styles["Heading2"])
    )

    for rec in report_data["recommendations"]:
        content.append(
            Paragraph(rec, styles["Normal"])
        )

    doc.build(content)

    buffer.seek(0)

    return buffer
