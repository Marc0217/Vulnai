from fastapi import APIRouter
from pydantic import BaseModel

from app.services.ai_chat import ask_ai_about_report

router = APIRouter()


class AIChatRequest(BaseModel):
    job_id: str
    question: str


@router.post("/ai/chat")
def ai_chat(request: AIChatRequest):

    answer = ask_ai_about_report(
        request.job_id,
        request.question
    )

    return {
        "job_id": request.job_id,
        "question": request.question,
        "answer": answer
    }
