FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ensat ./ensat
COPY scope.example.txt .env.example ./
ENV ENSAT_DATA_DIR=/app/data ENSAT_REPORT_DIR=/app/reports ENSAT_LOG_DIR=/app/logs PYTHONUNBUFFERED=1
VOLUME ["/app/data", "/app/reports"]
EXPOSE 8501
# Dashboard by default; override the command for CLI use, e.g.:
#   docker run --rm --network host ensat python -m ensat assess 192.168.56.10
CMD ["python", "-m", "streamlit", "run", "ensat/dashboard/app.py", "--server.address=0.0.0.0", "--server.headless=true", "--browser.gatherUsageStats=false"]
