FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 80

CMD ["sh", "-c", "streamlit run app.py --server.address=${UI_SERVICE_HOST:-0.0.0.0} --server.port=${UI_SERVICE_PORT:-80}"]
