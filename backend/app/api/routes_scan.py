from fastapi import APIRouter

from app.services.scanner import run_nmap_scan

router = APIRouter()


@router.post("/scan")
def scan(target: str):

    data = run_nmap_scan(target)

    return {
        "target": target,
        "ports": data["parsed"],
        "recommendations": data["advice"]
    }
