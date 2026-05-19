# LandauVPN — Модульное приложение для управления VPN и проксирования

## 📋 Описание

LandauVPN — это переработанная версия скрипта для управления VPN подключениями с добавлением функционала постоянного проксирования в стиле **zapret-discord-youtube**. Приложение позволяет:

- Управлять VPN профилями (OpenVPN, WireGuard, VPNGate)
- Получать бесплатные серверы с VPNGate
- **Постоянно проксировать трафик** для обхода блокировок Telegram, Discord, YouTube
- Работать как аналог zapret-discord-youtube для постоянного обхода DPI

## 🚀 Быстрый старт

### Запуск из исходного кода

```bash
# Установка зависимостей
pip install customtkinter requests

# Запуск приложения
python -m landauvpn.main
# или
python main.py
```

### Запуск через исполняемый файл (.exe)

#### Windows
1. Скачайте готовый `.exe` файл из релиза или соберите самостоятельно
2. Запустите `LandauVPN.exe`

#### Linux
```bash
./dist/LandauVPN
```

## 🏗️ Структура проекта

```
landauvpn/
├── __init__.py              # Инициализация пакета
├── main.py                  # Точка входа приложения
├── vpn_servers.json         # Кэш бесплатных VPN серверов
├── pyproject.toml           # Конфигурация проекта (для pip install)
├── landauvpn.spec           # Spec-файл для PyInstaller
├── build.sh                 # Скрипт сборки для Linux/Mac
│
├── core/                    # Ядро приложения
│   ├── __init__.py
│   ├── models.py            # Модель данных VPNProfile и функции парсинга
│   └── vpn_controller.py    # Контроллер управления VPN подключениями
│
├── proxy/                   # Модуль проксирования (zapret-style)
│   ├── __init__.py
│   └── controller.py        # ProxyController для постоянного проксирования
│
├── gui/                     # Графический интерфейс
│   ├── __init__.py
│   └── main_window.py       # Основное окно приложения
│
└── utils/                   # Утилиты
    ├── __init__.py
    └── config.py            # Конфигурация, пути, авторизация
```

## 📦 Сборка исполняемого файла (.exe)

### Автоматическая сборка (Linux/Mac)

```bash
chmod +x build.sh
./build.sh
```

### Ручная сборка

#### 1. Установка зависимостей

```bash
pip install customtkinter requests pyinstaller
```

#### 2. Сборка через PyInstaller

```bash
# Для всех платформ
pyinstaller landauvpn.spec --clean

# Или напрямую с опциями
pyinstaller --onefile --windowed --name LandauVPN main.py
```

#### 3. Результат

После сборки исполняемый файл будет находиться в папке `dist/`:
- **Windows**: `dist/LandauVPN.exe`
- **Linux**: `dist/LandauVPN`
- **macOS**: `dist/LandauVPN.app`

## 🔧 Настройка для разных платформ

### Windows

Для сборки под Windows используйте команду:

```bash
pyinstaller landauvpn.spec --clean
```

Или создайте свой spec-файл с опцией `console=False` для GUI приложения.

### Linux

```bash
./build.sh
```

### macOS

```bash
pyinstaller landauvpn.spec --clean --windowed
```

## ⚙️ Конфигурация

После первого запуска в домашней директории создаётся папка `.LandauVPN` со следующими файлами:

- `auth.json` — учётные данные администратора
- `vpn_profiles.json` — пользовательские VPN профили
- `profiles/` — загруженные конфигурации VPN
- `discord_hosts.txt`, `youtube_hosts.txt`, `telegram_hosts.txt` — списки хостов для прокси

## 🛠️ Требования

- Python 3.8+
- customtkinter >= 5.2.0
- requests >= 2.31.0
- PyInstaller >= 6.0.0 (для сборки .exe)

### Системные зависимости

#### Linux
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk openvpn wireguard-tools

# Fedora/RHEL
sudo dnf install python3-tk openvpn wireguard-tools
```

#### Windows
- [Visual C++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe)
- OpenVPN или WireGuard (опционально)

## 📝 Лицензия

MIT License
