FROM python:3.14-alpine
WORKDIR /app

RUN apk add --no-cache gcc musl-dev

COPY saferelay/ /app/saferelay/
COPY setup.py /app/
COPY README.md /app/

RUN pip install --no-cache-dir -e ".[redis]" && \
    apk del gcc musl-dev

RUN adduser -D saferelay
USER saferelay

ENTRYPOINT ["saferelay"]
