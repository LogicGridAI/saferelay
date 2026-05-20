FROM python:3.12-slim

WORKDIR /app

COPY safepaste_v3.4.1.py /app/safepaste.py

RUN pip install --no-cache-dir redis

RUN ln -s /app/safepaste.py /usr/local/bin/safepaste && \
    chmod +x /app/safepaste.py

ENTRYPOINT ["python", "/app/safepaste.py"]
