# Backend Nemesis Cyber Defense -- API (FastAPI)
FROM python:3.11-slim

WORKDIR /app

# gcc: compilar algunas dependencias de tensorflow/scikit-learn.
# iputils-ping + iproute2: usados por dispositivos_red.py (ping sweep +
#   `ip neigh`) para el inventario de dispositivos LAN, SIN Npcap.
# libpcap-dev: solo necesario si se activa el backend opcional "scapy".
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    iputils-ping \
    iproute2 \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# NET_ADMIN/NET_RAW son necesarios en tiempo de ejecución (docker run --cap-add)
# para que scapy pueda capturar paquetes de red real dentro del contenedor.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
