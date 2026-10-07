"""
Streamlit SOC Analyst Dashboard Entrypoint
Points directly to root app.py for backward compatibility.
"""
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

root_app = ROOT_DIR / "app.py"
with open(root_app, "r", encoding="utf-8") as f:
    code = f.read()

exec(compile(code, str(root_app), "exec"))
