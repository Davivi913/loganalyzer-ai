from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path
import os
from log_parser import parse_logs
from analyzer import analyze_with_ai
from models import AnalysisResult

app = FastAPI(title="LogAnalyzer AI", version="1.0.0")

if Path("/app/frontend").exists():
    FRONTEND_DIR = Path("/app/frontend")
else:
    FRONTEND_DIR = Path(__file__).parent.parent / "frontend"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/")
def root():
    return FileResponse(str(FRONTEND_DIR / "index.html"))

@app.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0"}

@app.post("/analyze", response_model=AnalysisResult)
async def analyze_logs(file: UploadFile = File(...)):
    if not file.filename.endswith((".log", ".txt")):
        raise HTTPException(400, "Solo se aceptan archivos .log o .txt")
    
    content_bytes = await file.read()
    
    if len(content_bytes) > 5 * 1024 * 1024:
        raise HTTPException(400, "Archivo demasiado grande (máximo 5MB)")
    
    try:
        content = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content = content_bytes.decode("latin-1")

    entries, log_type, suspicious = parse_logs(content)
    result = analyze_with_ai(suspicious, log_type, len(entries))
    
    return result