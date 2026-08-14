# 🛡️ LandauVPN — Интеллектуальная система обхода блокировок нового поколения

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)

**Единое решение для безопасного доступа к интернету: VPN + DPI Bypass + MTProto Proxy**

[Быстрый старт](#-быстрый-старт) • [Возможности](#-ключевые-возможности) • [Архитектура](#-архитектура-проекта) • [API](#-api-модулей) • [Сборка](#-сборка-приложения)

</div>

---

## 📖 О проекте

**LandauVPN** — это мощное кроссплатформенное приложение с графическим интерфейсом, которое объединяет передовые технологии обхода интернет-цензуры в едином интуитивно понятном интерфейсе. 

### Почему LandauVPN?

В эпоху массовых блокировок и глубокого анализа трафика (DPI), обычные VPN-решения часто оказываются неэффективными. LandauVPN предлагает **гибридный подход**:

| Технология | Назначение | Преимущества |
|------------|------------|--------------|
| **🔒 Полноценный VPN** | Шифрование всего трафика | OpenVPN, WireGuard, VPNGate |
| **⚡ DPI Bypass** | Избирательный обход блокировок | Минимальные задержки, работа без VPN |
| **✈️ MTProto Proxy** | Прокси для Telegram | Автопоиск, проверка, ранжирование |

### Ключевые особенности

- 🎯 **Умное переключение** — автоматически выбирает оптимальный метод обхода блокировок
- 🔍 **Автопоиск прокси** — сканирует публичные источники (Telegram, GitHub) для поиска рабочих MTProto прокси
- 🚀 **Асинхронная архитектура** — многопоточная проверка соединений без блокировки интерфейса
- 🛡️ **Приватность** — локальное хранение данных, шифрование чувствительной информации
- 🎨 **Современный UI** — интуитивный интерфейс на базе CustomTkinter

> 💡 **Вдохновение**: Приложение создано под влиянием утилит семейства **zapret**, но ориентировано на обычных пользователей благодаря удобному графическому интерфейсу.

---

## ✨ Ключевые возможности

### 🔹 Управление VPN-подключениями

Полноценная поддержка современных VPN-протоколов:

- ✅ **OpenVPN** — классический протокол с открытым исходным кодом
- ✅ **WireGuard** — современный высокоскоростной протокол
- ✅ **VPNGate** — интеграция с сетью бесплатных серверов
- ✅ **Импорт/экспорт** — загрузка `.ovpn` и `.conf` файлов
- ✅ **Быстрое переключение** — смена профиля в один клик

### 🔹 Интеллектуальный DPI Bypass

Обход систем глубокого анализа трафика без потери скорости:

| Сервис | Функциональность |
|--------|------------------|
| 📱 **Telegram** | Полный доступ к сообщениям, медиа и звонкам |
| 🎮 **Discord** | Стабильное соединение с голосовыми каналами |
| 📺 **YouTube** | Стриминг в любом качестве без буферизации |

**Преимущества:**
- ⚡ Работает в фоновом режиме без постоянного VPN
- 🎯 Селективное применение только к заблокированным ресурсам
- ⚙️ Гибкая настройка списков доменов
- 📊 Минимальное влияние на скорость соединения

### 🔹 MTProto Proxy с автопоиском

Встроенная система поиска и управления прокси для Telegram:

#### Источники поиска
- 🌐 **Telegram каналы** — парсинг публичных каналов через веб-API
- 💻 **GitHub репозитории** — мониторинг популярных списков прокси
- 🔗 **URL форматы** — поддержка `tg://proxy`, `https://t.me/proxy`, `proxy://`

#### Автоматизация
- 🔄 **Многопоточная проверка** — асинхронное тестирование работоспособности
- 📈 **Ранжирование по latency** — автоматический выбор fastest прокси
- 🧹 **Очистка нерабочих** — исключение прокси с большим количеством ошибок
- ➕ **Обновление списка** — добавление новых найденных прокси

#### Поддерживаемые типы секретов
- `plain` — стандартный hex-секрет
- `dd` — secret с префиксом `dd` (TLS-обфускация)
- `ee` — secret с префиксом `ee` (TLS-обфускация)

### 🔹 Безопасность и конфиденциальность

- 🔐 **Локальное хранение** — все данные сохраняются только на вашем устройстве
- 🔒 **Шифрование** — чувствительные данные (пароли, секреты) шифруются перед записью
- 👁️ **Открытый код** — полная прозрачность, возможность аудита сообществом
- 🚫 **Без телеметрии** — никакой отправки данных о использовании

---

## 🚀 Быстрый старт

### ▶️ Запуск из исходного кода

```bash
# Клонируйте репозиторий
git clone https://github.com/yourusername/landauvpn.git
cd landauvpn

# Установите зависимости
pip install -r requirements.txt
# или вручную:
pip install customtkinter requests aiohttp

# Запустите приложение
python -m landauvpn.main
# или
python main.py
```

### ▶️ Запуск готового приложения

#### Windows
1. Скачайте последнюю версию из [Releases](../../releases)
2. Запустите `LandauVPN.exe`
3. При необходимости предоставьте права администратора

#### Linux
```bash
# Скачайте бинарный файл
chmod +x dist/LandauVPN
./dist/LandauVPN
```

#### macOS
```bash
open dist/LandauVPN.app
```

---

## 🏗️ Архитектура проекта

LandauVPN следует принципам **чистой архитектуры** с четким разделением ответственности между модулями:

```
landauvpn/
├── main.py                  # 🚀 Точка входа, инициализация GUI
├── pyproject.toml           # 📦 Зависимости и метаданные проекта
├── landauvpn.spec           # 🔧 Конфигурация PyInstaller для сборки
├── build.sh                 # 🤖 Скрипт автоматической сборки
│
├── core/                    # 🧠 Ядро системы
│   ├── models.py            # 📊 Модели данных: VPNProfile, ProxyInfo
│   └── vpn_controller.py    # 🎮 VPNController: старт/стоп подключений
│
├── mtproto/                 # 📡 MTProto прокси для Telegram
│   └── controller.py        # 🔍 MTProtoController:
│                            #   • auto_search_proxies() — автопоиск из источников
│                            #   • search_proxies_from_telegram_channels()
│                            #   • search_proxies_from_github()
│                            #   • _parse_proxy_from_url() — парсинг URL
│                            #   • update_proxy_list() — обновление базы
│                            #   • test_proxy() — асинхронная проверка
│                            #   • get_working_proxies() — фильтрация рабочих
│
├── proxy/                   # 🌐 Система DPI Bypass
│   └── controller.py        # ⚡ ProxyController:
│                            #   • Селективное проксирование по доменам
│                            #   • Поддержка режимов: auto, telegram, discord, youtube
│                            #   • Интеграция с системными настройками прокси
│
├── dpi/                     # 🔓 Техники обхода DPI
│   └── bypasser.py          # 🛠️ DPIBypasser:
│                            #   • Low-level манипуляции с пакетами
│                            #   • Поддержка различных стратегий обхода
│
├── gui/                     # 🎨 Графический интерфейс
│   └── main_window.py       # 🖼️ LandauVPNGUI (CustomTkinter):
│                            #   • Вкладки: VPN профили, Бесплатные VPN, Прокси, Настройки
│                            #   • Кнопка «🔍 Поиск прокси» для MTProto
│                            #   • Лог событий в реальном времени
│                            #   • Статус-бар с состоянием подключений
│
└── utils/                   # 🛠️ Утилиты
    └── config.py            # ⚙️ Конфигурация:
                                • ensure_config_dirs()
                                • load/save_admin_auth()
                                • load/save_profiles()
                                • fetch_vpngate_profiles()
```

### API ключевых модулей

#### MTProtoController

```python
from landauvpn.mtproto.controller import MTProtoController, MTProtoProxy

controller = MTProtoController(log_func=print)

# Автоматический поиск прокси из всех источников
proxies = controller.auto_search_proxies(max_proxies=50)

# Поиск из конкретных источников
tg_proxies = controller.search_proxies_from_telegram_channels()
gh_proxies = controller.search_proxies_from_github()

# Парсинг прокси из URL
proxy = controller._parse_proxy_from_url("tg://proxy?server=1.2.3.4&port=80&secret=...")

# Обновление списка прокси
added = controller.update_proxy_list(new_proxies)

# Проверка работоспособности
is_working = controller.test_proxy(proxy)
working_list = controller.get_working_proxies()
```

#### Таблица модулей

| Модуль | Классы | Методы | Назначение |
|--------|--------|--------|------------|
| `core` | `VPNProfile`, `VPNController` | `start()`, `stop()` | Управление VPN |
| `mtproto` | `MTProtoController`, `MTProtoProxy` | `auto_search_proxies()`, `test_proxy()` | Прокси Telegram |
| `proxy` | `ProxyController`, `ProxyConfig` | `start()`, `stop()` | DPI Bypass |
| `dpi` | `DPIBypasser`, `DPIConfig` | `bypass()` | Low-level обход |
| `gui` | `LandauVPNGUI` | — | Пользовательский интерфейс |
| `utils` | Функции конфига | `load_*()`, `save_*()` | Конфигурация |

---

## 📦 Сборка исполняемого файла

### 🤖 Автоматическая сборка (Linux/macOS)

```bash
chmod +x build.sh
./build.sh
```

### 🔧 Ручная сборка

#### 1. Подготовка окружения

```bash
pip install customtkinter requests aiohttp pyinstaller>=6.0.0
```

#### 2. Компиляция через PyInstaller

```bash
# Использование spec-файла (рекомендуется)
pyinstaller landauvpn.spec --clean

# Или прямая сборка
pyinstaller --onefile --windowed --name LandauVPN main.py
```

#### 3. Результат

Готовый бинарный файл появится в директории `dist/`:

| Платформа | Файл |
|-----------|------|
| Windows | `dist/LandauVPN.exe` |
| Linux | `dist/LandauVPN` |
| macOS | `dist/LandauVPN.app` |

### 🖥️ Платформо-специфичные настройки

#### Windows
```bash
pyinstaller landauvpn.spec --clean
```
> 💡 Совет: Для скрытия консоли используйте `console=False` в spec-файле

#### Linux
```bash
./build.sh
```
> ⚠️ Требуются системные пакеты: `python3-tk`, `openvpn`, `wireguard-tools`

#### macOS
```bash
pyinstaller landauvpn.spec --clean --windowed
```

---

## ⚙️ Конфигурация и хранение данных

При первом запуске LandauVPN создаёт директорию конфигурации в домашней папке пользователя:

### 📁 Структура `.LandauVPN/`

```
~/.LandauVPN/
├── auth.json              # Учётные данные (хешированный пароль)
├── vpn_profiles.json      # Список сохранённых VPN профилей
├── mtproto_proxies.json   # База MTProto прокси с метриками
├── config.json            # Основные настройки приложения
│
├── profiles/              # Импортированные VPN конфигурации
│   ├── profile_1.ovpn
│   └── profile_2.conf
│
└── hosts/                 # Списки доменов для DPI bypass
    ├── telegram_hosts.txt
    ├── discord_hosts.txt
    └── youtube_hosts.txt
```

### 🔐 Формат хранения чувствительных данных

- Пароли хранятся в хешированном виде (SHA-256 + salt)
- Прокси секреты шифруются перед записью
- Конфигурационные файлы имеют ограничения доступа (chmod 600)

---

## 🛠️ Требования и зависимости

### Программные требования

| Компонент | Версия | Назначение |
|-----------|--------|------------|
| Python | 3.8+ | Базовая платформа |
| customtkinter | ≥5.2.0 | Современный GUI |
| requests | ≥2.31.0 | HTTP запросы |
| aiohttp | ≥3.9.0 | Асинхронные операции |
| PyInstaller | ≥6.0.0 | Сборка executables |

### Системные зависимости

#### 🐧 Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install -y python3-tk openvpn wireguard-tools
```

#### 🐧 Linux (Fedora/RHEL)
```bash
sudo dnf install -y python3-tk openvpn wireguard-tools
```

#### 🪟 Windows
- [Visual C++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe)
- OpenVPN Connect (опционально, для импорта .ovpn файлов)
- WireGuard (опционально, для .conf файлов)

#### 🍎 macOS
```bash
brew install python-tk openvpn wireguard-tools
```

---

## 📚 Дополнительная документация

- [🔄 Автообновление прокси](AUTO_UPDATE_FEATURE.md) — описание системы автоматического поиска MTProto прокси
- [⚡ Асинхронная работа MTProto](MTPROTO_ASYNC_FEATURES.md) — технические детали реализации
- [🌐 Прокси функциональность](PROXY_FEATURES.md) — руководство по использованию DPI bypass
- [📋 История изменений](CHANGES_MTPROTO_ASYNC.md) — лог обновлений и улучшений

---

## 🤝 Вклад в проект

Мы приветствуем contributions от сообщества! Если вы хотите помочь:

1. Создайте fork репозитория
2. Создайте feature branch (`git checkout -b feature/amazing-feature`)
3. Закоммитьте изменения (`git commit -m 'Add amazing feature'`)
4. Отправьте в remote (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

### 📝 Guidelines для контрибьюторов
- Следуйте PEP 8 для Python кода
- Добавляйте тесты для новых функций
- Обновляйте документацию при изменении API
- Используйте осмысленные commit messages

---

## ⚖️ Лицензия

Этот проект распространяется под лицензией **MIT License** — см. файл [LICENSE](LICENSE) для деталей.

### 📄 Краткое содержание лицензии
- ✅ Свободное использование в коммерческих и личных целях
- ✅ Возможность модификации и распространения
- ✅ Отсутствие гарантий и ограничений ответственности
- ℹ️ Требуется сохранение уведомления об авторских правах

---

## 📬 Контакты и поддержка

- 🐛 **Баг репорты**: Создайте issue в разделе [Issues](../../issues)
- 💡 **Предложения**: Обсуждения в [Discussions](../../discussions)
- 📧 **Email**: [ваш email]

---

<div align="center">

**LandauVPN** — Свободный интернет в один клик! 🌍✨

*Сделано с ❤️ для свободного интернета*

</div>
