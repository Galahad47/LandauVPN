# LandauVPN — Модульное приложение для управления VPN и проксирования

## 📋 Описание

LandauVPN — это переработанная версия скрипта для управления VPN подключениями с добавлением функционала постоянного проксирования в стиле **zapret-discord-youtube**. Приложение позволяет:

- Управлять VPN профилями (OpenVPN, WireGuard, VPNGate)
- Получать бесплатные серверы с VPNGate
- **Постоянно проксировать трафик** для обхода блокировок Telegram, Discord, YouTube
- Работать как аналог zapret-discord-youtube для постоянного обхода DPI

## 🏗️ Структура проекта

```
landauvpn/
├── __init__.py              # Инициализация пакета
├── main.py                  # Точка входа приложения
├── vpn_servers.json         # Кэш бесплатных VPN серверов
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

## 🚀 Установка

### Требования

- Python 3.8+
- customtkinter
- requests
- OpenVPN или WireGuard (для VPN подключений)
- zapret или goodbyedpi (для проксирования)

### Установка зависимостей

```bash
pip install customtkinter requests
```

### Установка инструментов для проксирования

#### Linux (zapret)
```bash
git clone https://github.com/bol-van/zapret.git
cd zapret
./install/install.sh
```

#### Windows (goodbyedpi)
```bash
# Скачайте релиз с https://github.com/ValdikSS/GoodbyeDPI/releases
# Распакуйте в ~/.LandauVPN/goodbyedpi/
```

## 💡 Использование

### Запуск приложения

```bash
cd /workspace
python -m landauvpn.main
```

Или напрямую:

```bash
python landauvpn/main.py
```

### Вкладки интерфейса

#### 🌐 VPN профили
- Список всех профилей (локальные + бесплатные)
- Подключение/отключение VPN
- Управление профилями

#### 🆓 Бесплатные VPN
- Получение серверов с VPNGate
- Фильтрация по странам, хостам
- Быстрое подключение к лучшему серверу

#### 🔒 Прокси (DPI) — НОВое!
- **Режимы работы:**
  - `auto` — автоматический выбор
  - `discord` — проксирование только Discord
  - `youtube` — проксирование только YouTube
  - `telegram` — проксирование только Telegram
  - `all` — проксирование всего трафика

- **Работает постоянно** — независимо от VPN
- **Аналог zapret-discord-youtube** — использует те же принципы обхода DPI

#### ➕ Добавить профиль
- Добавление своих .ovpn/.conf файлов
- Поддержка URL и vpngate:// ссылок

#### ⚙️ Настройки
- Смена логина/пароля администратора
- Обновление пула бесплатных VPN

## 🔧 API для разработчиков

### Использование модулей

```python
from landauvpn.core import VPNProfile, VPNController, fetch_vpngate_profiles
from landauvpn.proxy import ProxyController, ProxyConfig
from landauvpn.utils import load_admin_auth, CONFIG_DIR

# Получение бесплатных профилей
profiles = fetch_vpngate_profiles(limit=50)

# Создание VPN контроллера
def log_func(msg): print(msg)
vpn = VPNController(log_func)

# Запуск прокси для Telegram
proxy = ProxyController(log_func)
config = ProxyConfig(enabled=True, mode="telegram")
proxy.start(config)
```

### ProxyConfig параметры

```python
@dataclass
class ProxyConfig:
    enabled: bool = True          # Включено ли прокси
    mode: str = "auto"            # Режим: auto, discord, youtube, telegram, all
    custom_args: str = ""         # Дополнительные аргументы
    log_file: str = ""            # Файл логов
```

## 📁 Файлы конфигурации

Все файлы хранятся в `~/.LandauVPN/`:

- `auth.json` — учётные данные администратора
- `vpn_profiles.json` — пользовательские профили
- `profiles/` — загруженные конфиги VPN
- `discord_hosts.txt` — список хостов Discord
- `youtube_hosts.txt` — список хостов YouTube
- `telegram_hosts.txt` — список хостов Telegram

## 🔐 Авторизация

По умолчанию:
- Логин: `admin`
- Пароль: (пустой)

**Рекомендуется установить пароль при первом запуске!**

## ⚠️ Важные замечания

1. **Для работы VPN** требуется установленный OpenVPN или WireGuard
2. **Для работы прокси** требуется zapret (Linux) или goodbyedpi (Windows)
3. **На Linux/macOS** для запуска VPN может потребоваться sudo без пароля
4. **Прокси работает постоянно** — не забывайте останавливать его при необходимости

## 📝 Отличия от оригинального скрипта

| Оригинал | LandauVPN |
|----------|-----------|
| Монолитный скрипт | Модульная структура |
| Только VPN | VPN + Постоянное проксирование |
| Нет разделения | Чёткое разделение на core/proxy/gui/utils |
| Ручное управление | Автоматическое создание hostlists |

## 🛠️ Разработка

### Добавление нового режима прокси

1. Откройте `landauvpn/proxy/controller.py`
2. Добавьте режим в `_build_zapret_command()` и `_build_goodbyedpi_command()`
3. Обновите список хостов в `create_default_hostlists()`

### Сборка в .exe

```bash
pip install pyinstaller
pyinstaller --onefile --windowed landauvpn/main.py --name LandauVPN
```

## 📄 Лицензия

MIT License

## 🙏 Благодарности

- [VPNGate](https://www.vpngate.net/) — бесплатные VPN серверы
- [zapret](https://github.com/bol-van/zapret) — обход DPI
- [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) — обход DPI для Windows
- [customtkinter](https://github.com/TomSchimansky/CustomTkinter) — современный GUI
