FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY ingest.py .
CMD ["python","ingest.py","--watch","/data"]
