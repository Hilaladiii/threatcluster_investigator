FROM python:3.10 AS builder

WORKDIR /app

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"


FROM python:3.10-slim

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv

COPY --from=builder /root/.cache /root/.cache

COPY ./helper ./helper
COPY main.py .
COPY entrypoint.sh .

RUN sed -i 's/\r$//' entrypoint.sh 
RUN chmod +x entrypoint.sh

EXPOSE 8000

ENV PATH="/opt/venv/bin:$PATH"

ENTRYPOINT ["./entrypoint.sh"]