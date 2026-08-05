# Backend Nemesis Cyber Defense -- API (FastAPI)
FROM python:3.11-slim

WORKDIR /app

# Dependencias del sistema necesarias para scapy (captura de paquetes) y
# para compilar algunas dependencias de tensorflow/scikit-learn.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# NET_ADMIN/NET_RAW son necesarios en tiempo de ejecución (docker run --cap-add)
# para que scapy pueda capturar paquetes de red real dentro del contenedor.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
