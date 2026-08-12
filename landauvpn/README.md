# 🌐 LandauVPN — Универсальный инструмент для обхода блокировок и защиты приватности

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

**Мощное кроссплатформенное решение для управления VPN, MTProto прокси и интеллектуального обхода DPI**

[Быстрый старт](#-быстрый-старт) • [Возможности](#-ключевые-возможности) • [Документация](#-документация) • [Сборка](#-сборка-исполняемого-файла)

</div>

---

## 📖 О проекте

**LandauVPN** — это современное модульное приложение с графическим интерфейсом, объединяющее в себе лучшие инструменты для обхода интернет-цензуры. В отличие от традиционных VPN-клиентов, LandauVPN предлагает гибридный подход к защите вашего трафика:

- 🎯 **Интеллектуальное проксирование** — избирательный обход DPI для конкретных сервисов (Telegram, Discord, YouTube)
- 🔐 **Полноценные VPN подключения** — поддержка OpenVPN, WireGuard и бесплатных серверов VPNGate
- ⚡ **MTProto прокси** — встроенный поиск и управление прокси Telegram с автоматической проверкой работоспособности
- 🚀 **Производительность** — асинхронная архитектура и многопоточная проверка соединений

Приложение вдохновлено утилитами семейства **zapret**, но предоставляет удобный графический интерфейс и расширенный функционал для обычных пользователей.

---

## ✨ Ключевые возможности

### 🔹 Управление VPN подключениями
- ✅ Поддержка **OpenVPN** и **WireGuard** профилей
- ✅ Интеграция с **VPNGate** для получения бесплатных серверов
- ✅ Импорт/экспорт конфигураций
- ✅ Быстрое переключение между профилями

### 🔹 Умное проксирование (DPI Bypass)
- ✅ Постоянный фоновый режим проксирования
- ✅ Селективный обход блокировок для популярных сервисов:
  - 📱 **Telegram** — полный доступ без VPN
  - 🎮 **Discord** — стабильное соединение с голосовыми каналами
  - 📺 **YouTube** — беспрепятственный стриминг
- ✅ Настраиваемые списки доменов для каждого сервиса
- ✅ Минимальное влияние на скорость соединения

### 🔹 MTProto прокси (Telegram)
- ✅ **Автоматический поиск прокси** из публичных источников:
  - Telegram каналы и боты
  - GitHub репозитории
  - Прямые URL формата `tg://proxy` и `https://t.me/proxy`
- ✅ Многопоточная проверка работоспособности
- ✅ Рейтинг прокси по скорости отклика
- ✅ Автоматическое обновление списка рабочих прокси
- ✅ Поддержка всех типов секретов (plain, http_secret, tls_secret)

### 🔹 Безопасность и приватность
- ✅ Локальное хранение данных (никаких облачных сервисов)
- ✅ Шифрование чувствительной информации
- ✅ Открытый исходный код — полная прозрачность
- ✅ Отсутствие телеметрии и сбора данных

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

LandauVPN построен по принципу **модульности** и **разделения ответственности**:

```
landauvpn/
├── main.py                  # Точка входа и инициализация приложения
├── pyproject.toml           # Метаданные проекта и зависимости
├── landauvpn.spec           # Конфигурация сборки PyInstaller
├── build.sh                 # Автоматизация сборки для Unix-систем
│
├── core/                    # 🧠 Ядро системы
│   ├── models.py            # Модели данных (VPNProfile, ProxyInfo)
│   └── vpn_controller.py    # Управление VPN подключениями
│
├── mtproto/                 # 📡 MTProto прокси модуль
│   └── controller.py        # Поиск, проверка и управление прокси Telegram
│                            # • Автоматический парсинг из Telegram/GitHub
│                            # • Асинхронная проверка доступности
│                            # • Ранжирование по скорости
│
├── proxy/                   # 🌐 DPI Bypass система
│   └── controller.py        # ProxyController для селективного проксирования
│                            # • Обход блокировок Telegram, Discord, YouTube
│                            # • Работа в стиле zapret-discord-youtube
│
├── dpi/                     # 🔓 Низкоуровневые утилиты обхода DPI
│   └── bypasser.py          # Реализация техник обхода Deep Packet Inspection
│
├── gui/                     # 🎨 Графический интерфейс
│   └── main_window.py       # Главное окно приложения (CustomTkinter)
│                            # • Интуитивное управление всеми модулями
│                            # • Отображение статуса в реальном времени
│
└── utils/                   # 🛠️ Вспомогательные утилиты
    └── config.py            # Управление конфигурацией и путями
```

### Модульная структура

| Модуль | Ответственность | Ключевые классы |
|--------|----------------|-----------------|
| `core` | Базовая логика VPN | `VPNProfile`, `VPNController` |
| `mtproto` | Прокси Telegram | `MTProtoController` |
| `proxy` | Селективное проксирование | `ProxyController` |
| `dpi` | Техники обхода DPI | `DPIBypasser` |
| `gui` | Пользовательский интерфейс | `LandauVPNApp` |
| `utils` | Конфигурация и утилиты | `ConfigManager` |

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
