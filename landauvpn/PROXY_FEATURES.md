# 🛡️ LandauVPN - Новые возможности проксирования

## Обзор

В проект добавлены **три независимых метода** обхода блокировок для работы с Telegram, YouTube и другими сервисами:

---

## 1. 📡 Внешний прокси (zapret/goodbyedpi)

**Расположение:** `proxy/controller.py`

Использует внешние утилиты (zapret для Linux, goodbyedpi для Windows) для обхода DPI.

### Режимы работы:
- `auto` - автоматический выбор параметров
- `discord` - оптимизировано для Discord
- `youtube` - оптимизировано для YouTube
- `telegram` - оптимизировано для Telegram
- `all` - все сервисы сразу

### Использование в GUI:
1. Перейдите на вкладку "🔒 Прокси (DPI)"
2. Выберите режим работы
3. Нажмите "▶ Запустить внешний прокси"

---

## 2. 🛡️ Встроенный DPI обходчик (аналог zapret)

**Расположение:** `dpi/bypasser.py`

**Собственная реализация** обхода DPI внутри приложения, не требующая внешних утилит.

### Методы обхода:
- **TCP Segmentation** - разделение TCP пакетов на части
- **TTL Manipulation** - подделка TTL для обхода анализа
- **Fake Packets** - отправка поддельных пакетов для дезориентации DPI
- **HTTP Header Modification** - модификация заголовков HTTP (case changing, пробелы)

### Режимы работы:
- `auto` - автоматический выбор
- `youtube` - YouTube и связанные сервисы
- `telegram` - Telegram сервисы
- `all` - все популярные заблокированные сервисы

### API использование:
```python
from landauvpn.dpi import DPIBypasser, DPIConfig

dpi = DPIBypasser(log_func=print)
config = DPIConfig(mode="all", use_fake=True, use_split=True)
dpi.start(config)

# Добавление хоста
dpi.add_host("example.com")

# Обработка данных
packets = dpi.process_outgoing(data, hostname="example.com")
```

### Использование в GUI:
1. Перейдите на вкладку "🔒 Прокси (DPI)"
2. Найдите секцию "🛡️ Встроенный DPI обходчик"
3. Выберите режим и нажмите "▶ Запустить DPI обходчик"

---

## 3. ✈️ MTProto прокси (Telegram)

**Расположение:** `mtproto/controller.py`

Автоматическое подключение к **MTProto прокси** для работы Telegram.

### Возможности:
- **156 публичных MTProto прокси** от Telegram
- **Авто-выбор лучшего прокси** по доступности
- **Автоматическое переподключение** при обрыве
- **Тестирование прокси** перед подключением

### Формат прокси:
```python
MTProtoProxy(host="149.154.175.100", port=80, secret="ee0507dbf25e6e9c438a9eb097032d0545")
```

### API использование:
```python
from landauvpn.mtproto import MTProtoController, MTProtoConfig

mt = MTProtoController(log_func=print)

# Авто-выбор и подключение
config = MTProtoConfig(enabled=True, auto_detect=True)
mt.start(config)

# Добавить свой прокси
mt.add_proxy("host", 80, "secret")

# Проверка статуса
if mt.is_connected():
    proxy = mt.get_current_proxy()
    print(f"Подключено к: {proxy}")
```

### Использование в GUI:
1. Перейдите на вкладку "🔒 Прокси (DPI)"
2. Найдите секцию "✈️ MTProto прокси (Telegram)"
3. Включите "Авто-выбор лучшего прокси"
4. Нажмите "▶ Запустить MTProto"
5. Используйте кнопку "🔄 Тест прокси" для проверки доступности

---

## Сравнение методов

| Метод | Telegram | YouTube | Discord | Требует внешние утилиты |
|-------|----------|---------|---------|------------------------|
| Внешний прокси | ✅ | ✅ | ✅ | ✅ (zapret/goodbyedpi) |
| DPI обходчик | ✅ | ✅ | ✅ | ❌ (встроенный) |
| MTProto | ✅ | ❌ | ❌ | ❌ (встроенный) |

## Рекомендации

1. **Для Telegram**: Используйте MTProto прокси (наиболее надёжно) + DPI обходчик как резерв
2. **Для YouTube**: DPI обходчик или внешний прокси в режиме `youtube`
3. **Для всех сервисов**: Комбинируйте DPI обходчик (`all`) + MTProto

---

## Структура файлов

```
landauvpn/
├── dpi/
│   ├── __init__.py          # Экспорт модуля DPI
│   └── bypasser.py          # Встроенный DPI обходчик
├── mtproto/
│   ├── __init__.py          # Экспорт модуля MTProto
│   └── controller.py        # Контроллер MTProto прокси
├── proxy/
│   └── controller.py        # Внешний прокси (zapret/goodbyedpi)
└── gui/
    └── main_window.py       # Обновлённый интерфейс
```

---

## Примеры хостов

Файлы со списками хостов создаются автоматически в `~/.LandauVPN/`:
- `dpi_youtube_hosts.txt` - хосты YouTube
- `dpi_telegram_hosts.txt` - хосты Telegram
- `dpi_discord_hosts.txt` - хосты Discord
- `dpi_all_hosts.txt` - все хосты вместе

---

## Примечания

⚠️ **Внимание**: 
- Встроенный DPI обходчик работает на уровне приложения и требует интеграции с сетевым стеком
- Для полноценной работы может потребоваться запуск от имени администратора
- MTProto прокси работает только для трафика Telegram
- Внешний прокси требует установленные утилиты (zapret/goodbyedpi)
