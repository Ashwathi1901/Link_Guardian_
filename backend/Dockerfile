FROM python:3.10-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files and model assets
COPY main.py .
COPY zap_report.json .
COPY URL_model.joblib .
COPY email_model.joblib .
COPY email_content_converting_to_numbers.pkl .
COPY Email_phishing_keywords.pkl .
COPY metadata_URL.json .


EXPOSE 10000

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-10000}"]