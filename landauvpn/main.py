import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

from utils.config import ensure_config_dirs
from gui.main_window import LandauVPNGUI


def main():
    """Запуск приложения"""
    ensure_config_dirs()
    app = LandauVPNGUI()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()


if __name__ == "__main__":
    main()
