# SENTINEL — TrinTech Digital Defense
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt || true
COPY . .
ENV SENTINEL_DIR=/data
VOLUME ["/data"]
EXPOSE 8792
# Drop capabilities by default; document NET_RAW only if scanner needs raw sockets
CMD ["python3", "sentinel.py", "dash"]
