FROM python:3.9-alpine

RUN pip install --no-cache-dir authlib requests

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY .env /app/.env

COPY . .

ENV FLASK_APP=app.py
ENV FLASK_ENV=development

USER appuser

HEALTHCHECK --interval=30s --timeout=30s --retries=3 CMD curl -f http://localhost:5000/ || exit 1

CMD ["python", "app.py"]
