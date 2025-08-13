FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY rdap_exporter.py .

ENV PORT=8000
EXPOSE 8000

CMD ["python", "rdap_exporter.py"]
