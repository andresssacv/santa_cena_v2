import sys
import os

# Agregar directorio raíz para importar app.py y acceder a templates
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import app
