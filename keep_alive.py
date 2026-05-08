"""
keep_alive.py — Evita el "cold start" de Render plan gratuito
Hace un ping cada 10 minutos al servidor para mantenerlo despierto.

CÓMO USARLO:
  Importa e inicia desde app.py (ya incluido al final de app.py):
    from keep_alive import start_keep_alive
    start_keep_alive()

O ejecútalo de forma independiente:
  python keep_alive.py
"""

import threading
import time
import os
import urllib.request
import urllib.error

def ping_server():
    """Hace un GET al endpoint /health del propio servidor."""
    host = os.getenv("RENDER_EXTERNAL_URL") or os.getenv("APP_URL") or "http://localhost:5000"
    url = f"{host.rstrip('/')}/health"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "KeepAlive/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            print(f"[KeepAlive] ✅ Ping OK — {url} → HTTP {status}")
    except urllib.error.URLError as e:
        print(f"[KeepAlive] ⚠️  Ping fallido — {url}: {e.reason}")
    except Exception as e:
        print(f"[KeepAlive] ⚠️  Error inesperado: {e}")


def _loop(interval_seconds: int):
    while True:
        time.sleep(interval_seconds)
        ping_server()


def start_keep_alive(interval_minutes: int = 10):
    """
    Inicia el ping periódico en un hilo daemon.
    interval_minutes: cada cuántos minutos hace ping (default 10).
    """
    interval = interval_minutes * 60
    t = threading.Thread(target=_loop, args=(interval,), daemon=True)
    t.start()
    print(f"[KeepAlive] 🚀 Iniciado — ping cada {interval_minutes} min")


if __name__ == "__main__":
    print("[KeepAlive] Corriendo en modo standalone...")
    ping_server()
    _loop(interval_seconds=600)
