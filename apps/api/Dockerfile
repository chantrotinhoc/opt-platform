FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY apps/api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY apps/api/opt_api /app/opt_api
COPY engines /app/engines
ENV OPT_ENGINES_DIR=/app/engines
RUN useradd --system --uid 10001 opt
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --retries=12 CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/readyz')"
CMD ["uvicorn", "opt_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
