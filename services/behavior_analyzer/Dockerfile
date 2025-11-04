FROM selenium/standalone-chrome:latest

USER root
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
EXPOSE 8004
CMD ["python3", "app.py"]
