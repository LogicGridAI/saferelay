# SafeRelay CLI — minimal, dependency-free default image.
FROM python:3.14-alpine

RUN apk upgrade --no-cache && \
    pip install --no-cache-dir --upgrade pip setuptools

WORKDIR /app
COPY saferelay/ /app/saferelay/
COPY setup.py /app/
COPY README.md /app/

RUN pip install --no-cache-dir -e .

RUN adduser -D saferelay
USER saferelay

ENTRYPOINT ["saferelay"]
