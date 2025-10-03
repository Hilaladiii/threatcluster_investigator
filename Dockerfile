FROM python:3.10 AS builder

WORKDIR /app

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.10-slim

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv

COPY ./helper ./helper
COPY main.py .

ENV PATH="/opt/venv/bin:$PATH"

ENTRYPOINT ["python", "main.py"]