from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from concurrent.futures import ThreadPoolExecutor

from app.services.job_manager import (
    create_job,
    set_running,
    update_job,
    get_job,
    save_followup,
    save_ai_analysis
)

from app.services.scanner import run_nmap_scan
from app.services.nikto_scanner import run_nikto_scan
from app.services.whatweb_scanner import run_whatweb_scan
from app.services.nuclei_scanner import run_nuclei_scan
from app.services.gobuster_scanner import run_gobuster_scan
from app.services.sqlmap_scanner import run_sqlmap_scan
from app.services.ftp_scanner import run_ftp_scan
from app.services.ssh_scanner import run_ssh_scan
from app.services.smb_scanner import run_smb_scan
from app.services.mysql_scanner import run_mysql_scan

from app.services.report_generator import generate_report
from app.services.pdf_generator import generate_pdf_report
from app.services.ai_analyst import analyze_security_findings

router = APIRouter()


def safe_future_result(future, scanner_name, timeout=60):

    try:
        return future.result(timeout=timeout)

    except Exception as e:
        print(f"{scanner_name} failed: {e}")
        return []


def generate_and_cache_ai(job_id):

    report = generate_report(job_id)

    temp_report = {
        "target": report["target"],
        "ports": report["ports"],
        "findings": report["findings"],
        "risk_analysis": report["risk_analysis"]
    }

    ai_analysis = analyze_security_findings(temp_report)
    save_ai_analysis(job_id, ai_analysis)


@router.post("/jobs")
def create_scan_job(target: str):

    job_id = create_job(target)

    set_running(job_id)

    results = run_nmap_scan(target)

    update_job(job_id, results)

    return {
        "job_id": job_id,
        "status": "completed"
    }


@router.get("/jobs/{job_id}")
def get_job_status(job_id: str):

    return get_job(job_id)


@router.post("/approve_scan/{job_id}")
def approve_followup(job_id: str, ports: str = ""):

    job = get_job(job_id)

    if not job:
        return {"error": "Job not found"}

    target = job["target"]
    parsed_results = job.get("results", {}).get("parsed", [])

    if ports.strip():

        requested_ports = []

        for port in ports.split(","):
            try:
                requested_ports.append(int(port.strip()))
            except:
                continue

    else:
        requested_ports = [
            r["port"]
            for r in parsed_results
            if r.get("state") == "open"
        ]

    if not requested_ports:
        return {"error": "No valid ports selected"}

    service_map = {}

    for result in parsed_results:

        if result.get("state") != "open":
            continue

        port = result["port"]

        if port in requested_ports:
            service_map[port] = result.get("service", "").lower()

    followup_results = {}
    web_ports = []

    for port, service in service_map.items():

        if service in ["http", "http-proxy", "https"]:
            web_ports.append(port)

        elif service == "ftp":
            followup_results[f"ftp_{port}"] = run_ftp_scan(target, port)

        elif service == "ssh":
            followup_results[f"ssh_{port}"] = run_ssh_scan(target, port)

        elif service == "microsoft-ds":
            followup_results[f"smb_{port}"] = run_smb_scan(target, port)

        elif service == "mysql":
            followup_results[f"mysql_{port}"] = run_mysql_scan(target, port)

    if web_ports:

        with ThreadPoolExecutor(max_workers=4) as executor:

            nikto_future = executor.submit(run_nikto_scan, target, web_ports)
            whatweb_future = executor.submit(run_whatweb_scan, target, web_ports)
            nuclei_future = executor.submit(run_nuclei_scan, target, web_ports)
            gobuster_future = executor.submit(run_gobuster_scan, target, web_ports)

            followup_results["nikto"] = safe_future_result(nikto_future, "Nikto", 90)
            followup_results["whatweb"] = safe_future_result(whatweb_future, "WhatWeb", 30)
            followup_results["nuclei"] = safe_future_result(nuclei_future, "Nuclei", 60)
            followup_results["gobuster"] = safe_future_result(gobuster_future, "Gobuster", 60)

    save_followup(job_id, followup_results)

    generate_and_cache_ai(job_id)

    return {
        "job_id": job_id,
        "approved_action": "service_aware_followup",
        "selected_ports": requested_ports,
        "services_detected": service_map,
        "followup_results": followup_results
    }


@router.post("/approve_sqlmap/{job_id}")
def approve_sqlmap(job_id: str, url: str):

    job = get_job(job_id)

    if not job:
        return {"error": "Job not found"}

    sqlmap_results = run_sqlmap_scan(url)

    save_followup(job_id, {
        "sqlmap": sqlmap_results
    })

    generate_and_cache_ai(job_id)

    return {
        "job_id": job_id,
        "approved_action": "sqlmap_scan",
        "target_url": url,
        "results": sqlmap_results
    }


@router.get("/report/{job_id}")
def get_report(job_id: str):

    return generate_report(job_id)


@router.get("/report/{job_id}/pdf")
def download_pdf_report(job_id: str):

    report_data = generate_report(job_id)

    pdf = generate_pdf_report(report_data)

    return StreamingResponse(
        pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
            f"attachment; filename=vulnai_report_{job_id}.pdf"
        }
    )
