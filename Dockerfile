FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (cached layer — only rebuilds if requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir --default-timeout=120 -r requirements.txt

# Download ONNX model + tokenizer from HF Hub instead of baking in local weights.
# Keeps the image small and portable — Member C builds this without needing
# your local waf-distilbert-final_onnx/ folder at all.
RUN python -c "\
from huggingface_hub import snapshot_download; \
snapshot_download(repo_id='Shade63/waf-onnx', local_dir='waf-distilbert-final')"

# Copy application code
COPY proxy/ ./proxy/

EXPOSE 8000

CMD ["uvicorn", "proxy.model:app", "--host", "0.0.0.0", "--port", "8000"]