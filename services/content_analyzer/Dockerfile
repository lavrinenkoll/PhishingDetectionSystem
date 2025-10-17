FROM selenium/standalone-chrome:latest

USER root
WORKDIR /app

COPY requirements.txt .
RUN apt-get update && apt-get install -y python3 python3-pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8003
CMD ["python3", "app.py"]
