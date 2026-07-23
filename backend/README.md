---
title: Link Guardian Backend
emoji: 🛡️
sdk: docker
app_port: 7860
pinned: false
---

# 🛡️ Link Guardian Backend

FastAPI phishing detection microservice powering **Link Guardian**. Powered by XGBoost machine learning classifiers and OWASP ZAP security audit telemetry.

## Hugging Face Spaces Deployment & Cold Start Note

> [!NOTE]
> Hugging Face Spaces free tier containers sleep after 15-48 minutes of inactivity. The first request after idle will experience a **cold start delay (up to ~60 seconds)** while the container builds/wakes up and loads ML models into RAM.

## Environment Variables & Security

* `ALLOWED_ORIGIN`: **CRITICAL FOR PRODUCTION**. Set this environment variable in your Hugging Face Space settings (under **Settings -> Variables and secrets**) to your deployed Netlify frontend URL (e.g. `https://link-guardian.netlify.app`).
  * **Default (Dev)**: `http://localhost:8000,http://localhost:5500,http://localhost:3000,http://127.0.0.1:8000,http://127.0.0.1:5500,http://127.0.0.1:3000`
  * **Production**: Never set `ALLOWED_ORIGIN="*"` in production.
* `MODEL_PATH`: Directory path containing model files (defaults to `.`).
* `ZAP_REPORT_PATH`: Path to the parsed ZAP report JSON (defaults to `zap_report.json`).

## API Endpoints

* `GET /health`: Health check and cold-start wake-up endpoint. Returns `{"status": "ok"}`.
* `GET /api/zap-report`: Returns OWASP ZAP security audit summary and findings.
* `POST /api/analyze`: Accepts `{ "url": "...", "content": "..." }` and returns phishing verdict (`safe` | `suspicious` | `phishing`), confidence %, and dynamic risk signals.
* `GET /docs`: Interactive OpenAPI documentation.
