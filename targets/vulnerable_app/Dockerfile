FROM python:3.12-slim

WORKDIR /app
COPY app.py ./

USER nobody
EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/').read()"

# 0.0.0.0 is container-internal only; compose publishes it on loopback.
CMD ["python", "app.py", "--host", "0.0.0.0", "--port", "8080"]
