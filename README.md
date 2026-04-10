# LandauVPN

LandauVPN — настольное приложение на Python для управления VPN-профилями через графический интерфейс `customtkinter`.

Программа предназначена для администратора. Она позволяет входить по локальным учётным данным, загружать и подключать VPN-профили, работать с бесплатным пулом серверов VPNGate, а также запускать VPN-клиент для всей системы.

## Возможности

- вход по логину и паролю администратора
- хранение учётных данных в отдельном локальном файле `~/.LandauVPN/auth.json`
- поддержка профилей:
  - OpenVPN (`.ovpn`)
  - WireGuard (`.conf`)
  - VPNGate (`vpngate://hostname|ip`)
- загрузка профиля из локального файла или по URL
- отдельный файл со списком бесплатных серверов: `vpn_servers.json`
- обновление бесплатного списка из VPNGate
- поиск по спискам профилей и бесплатных серверов
- двойной клик по серверу для подключения
- запуск VPN в фоне без зависания интерфейса
- журнал действий внизу окна
- открытие папки профилей и файла авторизации из интерфейса
- изменение логина и пароля администратора в настройках

## Требования

- Python 3.10 или новее
- `customtkinter`
- `requests`
- установленный VPN-клиент:
  - OpenVPN для `.ovpn`
  - WireGuard для `.conf`

## Установка

### Через git

```bash
    git clone https://github.com/yourusername/LandauVPN.git
    cd LandauVPN
```

### Через загрузку архива

```bash
    curl -L -o LandauVPN.zip https://github.com/yourusername/LandauVPN/archive/refs/heads/main.zip
```

На Windows можно скачать архив через браузер с GitHub и распаковать его вручную.

## Установка зависимостей

```bash
    pip install customtkinter requests
```

## Запуск

```bash
    python landau_admin_vpn_manager_ux.py
```

Если проект собран в `.exe`, рядом с исполняемым файлом должен лежать `vpn_servers.json`.

## Структура проекта

```text
LandauVPN/
├── landau_admin_vpn_manager_ux.py
├── vpn_servers.json
├── README.md
└── .gitignore
```

После первого запуска программа создаёт локальные файлы в домашней папке пользователя:

```text
~/.LandauVPN/
├── auth.json
├── vpn_profiles.json
└── profiles/
```

## Авторизация администратора

По умолчанию:

- логин: `admin`
- пароль: `Konstruk.tor.16.`

Логин и пароль можно изменить во вкладке **Настройки**. После изменения данные сохраняются в `~/.LandauVPN/auth.json`.

## Как работает программа

Приложение не создаёт собственный VPN-туннель. Оно запускает системный VPN-клиент:

- для OpenVPN используется команда:

```bash
openvpn --config <файл>
```

- для WireGuard на Linux/macOS используется:

```bash
sudo wg-quick up <файл>
```

На Windows используется системная команда для установленного клиента.

Это означает, что VPN применяется ко всей системе, а не только к самому приложению.

## Бесплатные серверы VPN

Файл `vpn_servers.json` содержит список бесплатных профилей VPNGate.

Программа:

1. загружает этот файл при запуске;
2. показывает серверы во вкладке **Бесплатные VPN**;
3. может обновить список из VPNGate;
4. сохраняет обновлённый список обратно в JSON.

Если файла `vpn_servers.json` нет рядом с программой, приложение пытается найти его:

- рядом со скриптом или `.exe`
- в текущей рабочей папке
- в `~/.LandauVPN/`

## Формат `vpn_servers.json`

Пример записи:

```json
{
  "name": "VPNGate Japan #1 — public-vpn-257.opengw.net",
  "kind": "vpngate",
  "source": "vpngate://public-vpn-257.opengw.net|219.100.37.208",
  "local_path": "",
  "enabled": true,
  "note": "score 123456, ping 18 ms, speed 24567"
}
```

## Добавление собственного профиля

Во вкладке **Добавить профиль** можно указать:

- путь к локальному файлу `.ovpn` или `.conf`
- URL на конфиг
- VPNGate-формат `vpngate://hostname|ip`

Пример:

```text
vpngate://public-vpn-257.opengw.net|219.100.37.208
```

## Интерфейс

Во вкладках доступны:

- поиск по спискам
- обновление бесплатных серверов
- подключение выбранного профиля
- отключение VPN
- удаление и включение/выключение профилей
- проверка части профилей в фоне
- просмотр логов

## Команды для скачивания

### Скачать файл `vpn_servers.json`

```bash
curl -L -o vpn_servers.json https://raw.githubusercontent.com/yourusername/LandauVPN/main/vpn_servers.json
```

### Скачать основной скрипт

```bash
curl -L -o landau_admin_vpn_manager_ux.py https://raw.githubusercontent.com/yourusername/LandauVPN/main/landau_admin_vpn_manager_ux.py
```

### Скачать весь проект как ZIP

```bash
curl -L -o LandauVPN.zip https://github.com/yourusername/LandauVPN/archive/refs/heads/main.zip
```

## Troubleshooting

### VPN не запускается

Проверь:

- установлен ли OpenVPN или WireGuard
- существует ли выбранный файл конфига
- хватает ли прав для запуска VPN
- корректен ли сам конфиг

### Список бесплатных серверов пуст

Проверь:

- наличие файла `vpn_servers.json`
- доступ в интернет
- доступность VPNGate
- обновление списка через кнопку **Обновить из VPNGate**

### Не удаётся войти

Проверь файл:

```text
~/.LandauVPN/auth.json
```

Можно открыть его прямо из программы во вкладке **Настройки**.

## Безопасность

- пароль администратора хранится локально в виде SHA-256 хеша
- файлы `auth.json`, `vpn_profiles.json` и папка `profiles/` не должны попадать в репозиторий
- бесплатные VPN-сервера могут меняться и быть нестабильными

## Рекомендуемый `.gitignore`

```gitignore
auth.json
vpn_profiles.json
profiles/
__pycache__/
*.pyc
```

## Лицензия

Добавьте лицензию, которую хотите использовать в проекте, например MIT.
