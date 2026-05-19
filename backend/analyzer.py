import os
from groq import Groq
from typing import List
from models import AnalysisResult, Alert, SeverityLevel
from dotenv import load_dotenv
import json
import re

def analyze_with_ai(suspicious_lines, log_type, total_lines):
    print(f"DEBUG - API Key cargada: {os.getenv('GROQ_API_KEY')[:10] if os.getenv('GROQ_API_KEY') else 'NO ENCONTRADA'}")
    print(f"DEBUG - Líneas sospechosas: {len(suspicious_lines)}")

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def analyze_with_ai(suspicious_lines: List[str], log_type: str, total_lines: int) -> AnalysisResult:
    if not suspicious_lines:
        return AnalysisResult(
            total_lines=total_lines,
            suspicious_lines=0,
            alerts=[],
            summary="No se detectaron patrones sospechosos en los logs analizados.",
            log_type=log_type
        )

    sample = suspicious_lines[:30]
    lines_text = "\n".join(sample)

    prompt = f"""Eres un experto en ciberseguridad analizando logs de tipo '{log_type}'.
Analiza estas {len(suspicious_lines)} líneas sospechosas (muestra de {len(sample)}):

{lines_text}

Responde ÚNICAMENTE con un JSON válido con esta estructura exacta:
{{
  "summary": "resumen ejecutivo en 2-3 frases",
  "alerts": [
    {{
      "severity": "low|medium|high|critical",
      "title": "título corto del problema",
      "description": "descripción detallada de qué está pasando",
      "affected_lines": [1, 2, 3],
      "recommendation": "qué hacer para mitigar esto"
    }}
  ]
}}

Agrupa problemas similares en una sola alerta. Máximo 5 alertas. Sin texto adicional, solo JSON."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=1500
    )

    raw = response.choices[0].message.content.strip()
    
    json_match = re.search(r'\{.*\}', raw, re.DOTALL)
    if json_match:
        raw = json_match.group()
    
    data = json.loads(raw)

    alerts = [
        Alert(
            severity=SeverityLevel(a["severity"]),
            title=a["title"],
            description=a["description"],
            affected_lines=a.get("affected_lines", []),
            recommendation=a["recommendation"]
        )
        for a in data.get("alerts", [])
    ]

    return AnalysisResult(
        total_lines=total_lines,
        suspicious_lines=len(suspicious_lines),
        alerts=alerts,
        summary=data.get("summary", ""),
        log_type=log_type
    )