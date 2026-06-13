from fastapi import FastAPI

from app.api.routes_scan import router as scan_router
from app.api.routes_jobs import router as jobs_router
from app.api.routes_ai import router as ai_router

from app.services.database import init_db

app = FastAPI()

init_db()

app.include_router(scan_router)
app.include_router(jobs_router)
app.include_router(ai_router)


@app.get("/")
def root():
    return {"msg": "VulnAI API running"}
