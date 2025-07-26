FROM python:3.14.0rc1-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# Create logs directory inside the container
RUN mkdir -p /logs

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000"]