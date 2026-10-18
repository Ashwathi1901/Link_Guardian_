import os
import re
import json
import joblib
import datetime
import traceback
import numpy as np
import scipy.sparse as sp
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator

# Environment Variable Configurations
MODEL_PATH = os.getenv("MODEL_PATH", ".")
ZAP_REPORT_PATH = os.getenv("ZAP_REPORT_PATH", "zap_report.json")
ALLOWED_ORIGIN_ENV = os.getenv("ALLOWED_ORIGIN", "")

# Default allowed origins for local dev (NO wildcard default!)
if ALLOWED_ORIGIN_ENV:
    ALLOWED_ORIGINS = [origin.strip() for origin in ALLOWED_ORIGIN_ENV.split(",") if origin.strip()]
else:
    ALLOWED_ORIGINS = [
        "http://localhost:8000",
        "http://localhost:5500",
        "http://localhost:3000",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:5500",
        "http://127.0.0.1:3000",
        "https://link-guardian-r2h7.onrender.com"
        "https://link-guardian-r2h7.onrender.com/docs#/default/analyze_api_analyze_post"
    ]

print("CORS allowed origins:", ALLOWED_ORIGINS) #to check
# Global cache for loaded models
ml_models: Dict[str, Any] = {}

def load_models_at_startup():
    """Load machine learning models once at application startup."""
    global ml_models
    try:
        url_model_path = os.path.join(MODEL_PATH, "URL_model.joblib")
        email_model_path = os.path.join(MODEL_PATH, "email_model.joblib")
        email_tfidf_path = os.path.join(MODEL_PATH, "email_content_converting_to_numbers.pkl")
        keywords_path = os.path.join(MODEL_PATH, "Email_phishing_keywords.pkl")
        metadata_path = os.path.join(MODEL_PATH, "metadata_URL.json")

        print(f"[INFO] Loading ML model artifacts from: {os.path.abspath(MODEL_PATH)}")
        ml_models["url_model"] = joblib.load(url_model_path)
        ml_models["email_model"] = joblib.load(email_model_path)
        
        email_tfidf = joblib.load(email_tfidf_path)
        # Patch sklearn TfidfTransformer version incompatibility if needed
        if hasattr(email_tfidf, "_tfidf") and "idf_" in email_tfidf._tfidf.__dict__ and not hasattr(email_tfidf._tfidf, "_idf_diag"):
            idf_arr = email_tfidf._tfidf.__dict__["idf_"]
            email_tfidf._tfidf._idf_diag = sp.diags(
                idf_arr, offsets=0, shape=(len(idf_arr), len(idf_arr)), format="csr", dtype=np.float64
            )
        ml_models["email_tfidf"] = email_tfidf
        ml_models["keywords"] = joblib.load(keywords_path)

        if os.path.exists(metadata_path):
            with open(metadata_path, "r", encoding="utf-8") as f:
                ml_models["metadata"] = json.load(f)

        print("[OK] ML models successfully loaded into memory.")
    except Exception as e:
        print(f"[ERROR] Error loading ML models at startup: {e}")
        traceback.print_exc()

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_models_at_startup()
    yield
    ml_models.clear()

app = FastAPI(
    title="🛡️ Link Guardian API",
    description="Phishing detection service analyzing email URLs and content.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS Middleware explicitly
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="Target URL to check for phishing indicators")
    content: Optional[str] = Field(default="", description="Optional email text body to check")

    @validator("url")
    def validate_url_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("URL field is required and cannot be empty.")
        return v.strip()

def extract_url_features(url: str) -> np.ndarray:
    """
    Computes 48 features from raw URL string matching metadata_URL.json schema.
    Extremely long URLs are handled safely without crashing.
    """
    # Truncate string if excessively long (e.g. >10,000 chars) to prevent regex slowdown
    if len(url) > 10000:
        url = url[:10000]

    # Prepend http:// scheme if missing for proper urllib parsing
    if not url.startswith(("http://", "https://")):
        url_to_parse = "http://" + url
    else:
        url_to_parse = url

    try:
        parsed = urlparse(url_to_parse)
        netloc = parsed.netloc or ""
        path = parsed.path or ""
        query = parsed.query or ""
        scheme = parsed.scheme or ""

        num_dots = url.count(".")
        subdomain_level = max(0, netloc.count(".") - 1) if netloc else 0
        path_level = path.count("/")
        url_len = len(url)
        num_dash = url.count("-")
        num_dash_host = netloc.count("-")
        at_sym = 1 if "@" in url else 0
        tilde_sym = 1 if "~" in url else 0
        num_underscore = url.count("_")
        num_percent = url.count("%")
        num_query_comp = len(query.split("&")) if query else 0
        num_ampersand = url.count("&")
        num_hash = url.count("#")
        num_numeric = sum(c.isdigit() for c in url)
        no_https = 1 if scheme.lower() != "https" else 0
        random_string = 0
        ip_address = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", netloc) else 0
        domain_in_subdomains = 0
        domain_in_paths = 0
        https_in_hostname = 1 if "https" in netloc.lower() else 0
        hostname_len = len(netloc)
        path_len = len(path)
        query_len = len(query)
        double_slash_path = 1 if "//" in path else 0
        
        sensitive_words = ["secure", "account", "update", "login", "signin", "bank", "verify", "password", "urgent", "pay", "confirm"]
        num_sensitive = sum(1 for w in sensitive_words if w in url.lower())

        subdomain_level_rt = -1 if subdomain_level > 2 else (0 if subdomain_level == 2 else 1)
        url_length_rt = -1 if url_len > 75 else (0 if url_len > 54 else 1)

        feats = [
            num_dots, subdomain_level, path_level, url_len, num_dash, num_dash_host,
            at_sym, tilde_sym, num_underscore, num_percent, num_query_comp, num_ampersand,
            num_hash, num_numeric, no_https, random_string, ip_address, domain_in_subdomains,
            domain_in_paths, https_in_hostname, hostname_len, path_len, query_len, double_slash_path,
            num_sensitive, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            subdomain_level_rt, url_length_rt, 1, 1, 1, 1
        ]
        return np.array([feats])
    except Exception as e:
        print(f"⚠️ Warning: Feature extraction failed for URL, returning default array: {e}")
        return np.zeros((1, 48))

@app.get("/health", summary="Health check endpoint")
async def health_check():
    """Returns 200 OK for status checking and wake-up pings."""
    return {"status": "ok", "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}

@app.get("/api/zap-report", summary="Retrieve OWASP ZAP security scan summary")
async def get_zap_report():
    """Serves parsed OWASP ZAP report data."""
    report_file = os.path.join(MODEL_PATH, ZAP_REPORT_PATH) if not os.path.isabs(ZAP_REPORT_PATH) else ZAP_REPORT_PATH
    if not os.path.exists(report_file):
        # Fallback search in current directory
        if os.path.exists("zap_report.json"):
            report_file = "zap_report.json"
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"ZAP report file '{ZAP_REPORT_PATH}' not found."
            )
    try:
        with open(report_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read ZAP security report: {str(e)}"
        )

@app.post("/api/analyze", summary="Analyze URL and email content for phishing risk")
async def analyze(req: AnalyzeRequest):
    """
    Accepts URL and optional email body text, processes through XGBoost ML classifiers,
    and returns risk verdict, confidence score, and dynamic reasoning signals.
    """
    raw_url = req.url.strip()
    if not raw_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL is required for analysis."
        )

    # Normalize scheme for raw URL if needed
    normalized_url = raw_url if raw_url.startswith(("http://", "https://")) else "http://" + raw_url

    if "url_model" not in ml_models:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Machine learning models are still loading. Please try again shortly."
        )

    reasons: List[str] = []
    
    # 1. URL Model Evaluation
    try:
        url_feats = extract_url_features(normalized_url)
        url_risk = float(ml_models["url_model"].predict_proba(url_feats)[0][1])
    except Exception as e:
        print(f"URL model prediction error: {e}")
        url_risk = 0.5
        reasons.append("Model warning: Standard URL evaluation default applied")

    # Dynamic URL Reason Signals
    parsed_netloc = urlparse(normalized_url).netloc
    if not normalized_url.startswith("https://"):
        reasons.append("Insecure HTTP protocol used (missing SSL/TLS encryption)")
    if "@" in raw_url:
        reasons.append("@ symbol present in URL (potential user credentials obfuscation)")
    if raw_url.count("-") > 3:
        reasons.append("Excessive hyphens found in domain/URL path")
    if len(raw_url) > 75:
        reasons.append("Unusually long URL length (> 75 characters)")
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", parsed_netloc):
        reasons.append("Raw IP address used as hostname instead of a verified domain name")
    
    sensitive_keywords = ["login", "verify", "account", "secure", "bank", "password", "update", "urgent", "pay", "signin"]
    matched_url_words = [w for w in sensitive_keywords if w in raw_url.lower()]
    if matched_url_words:
        reasons.append(f"High-risk credential harvesting keywords in URL: {', '.join(matched_url_words)}")

    # 2. Email Body Model Evaluation (if content is provided)
    email_risk = 0.0
    email_content = (req.content or "").strip()
    if email_content and "email_model" in ml_models:
        try:
            c_lower = email_content.lower()
            email_tfidf = ml_models["email_tfidf"]
            keywords = ml_models["keywords"]
            
            email_vec = email_tfidf.transform([c_lower])
            email_kw = np.array([[1 if w in c_lower else 0 for w in keywords]])
            email_dense = email_vec.toarray()
            
            if email_dense.shape[1] >= 100:
                email_dense = email_dense[:, -100:]
            else:
                pad_width = 100 - email_dense.shape[1]
                email_dense = np.pad(email_dense, ((0, 0), (0, pad_width)))
                
            email_combined = np.hstack([email_dense, email_kw])
            email_risk = float(ml_models["email_model"].predict_proba(email_combined)[0][1])
            
            kw_detected = [k for k, v in zip(keywords, email_kw[0]) if v]
            if kw_detected:
                reasons.append(f"Urgency/phishing keywords detected in email body: {', '.join(kw_detected)}")
            if email_risk > 0.6:
                reasons.append("Email text body matches high-risk phishing communication patterns")
        except Exception as e:
            print(f"Email model prediction error: {e}")

    # 3. Aggregate Risk Score & Verdict Calculation
    if email_content:
        final_risk = 0.6 * url_risk + 0.4 * email_risk
    else:
        final_risk = url_risk

    if final_risk >= 0.70:
        verdict = "phishing"
    elif final_risk >= 0.35:
        verdict = "suspicious"
    else:
        verdict = "safe"

    if not reasons:
        if verdict == "safe":
            reasons.append("Standard URL structure with HTTPS protocol")
            reasons.append("No known phishing indicators or domain anomalies detected")
        else:
            reasons.append("Anomalous URL structure flagged by machine learning classifier")

    confidence_pct = round(final_risk * 100.0, 1)

    return {
        "verdict": verdict,
        "confidence": confidence_pct,
        "reasons": reasons,
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "normalized_url": normalized_url
    }
