"""
LandauVPN - Main Entry Point
Точка входа приложения
"""

import sys
from pathlib import Path

# Добавляем корень проекта в путь
sys.path.insert(0, str(Path(__file__).resolve().parent))

from landauvpn.utils.config import ensure_config_dirs
from landauvpn.gui.main_window import LandauVPNGUI


def main():
    """Запуск приложения LandauVPN"""
    # Создание необходимых директорий
    ensure_config_dirs()
    
    # Запуск GUI
    app = LandauVPNGUI()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()


if __name__ == "__main__":
    main()
