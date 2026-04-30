FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY collector.py /app/collector.py

ENV CSV_FILE=/data/threat_intel.csv \
    INTERFACE=auto \
    BPF_FILTER= \
    ENABLE_RDNS=false \
    ENABLE_RDAP=true \
    PAYLOAD_MAX_BYTES=1024 \
    FLUSH_INTERVAL=1 \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]

CMD ["python", "/app/collector.py"]
