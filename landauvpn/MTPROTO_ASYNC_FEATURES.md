# Асинхронная проверка MTProto прокси в LandauVPN

## Обзор

Модуль `mtproto/controller.py` был полностью переработан с использованием **асинхронного программирования** для эффективной проверки доступности прокси-серверов.

## Ключевые возможности

### 1. Асинхронная проверка всех прокси параллельно

```python
import asyncio
from mtproto.controller import MTProtoController

controller = MTProtoController()

async def check():
    # Проверяет все прокси одновременно (параллельно)
    results = await controller.check_all_proxies_async()
    
    for proxy, is_working in results.items():
        if is_working:
            print(f"✓ {proxy.host}:{proxy.port} ({proxy.latency:.0f}ms)")

asyncio.run(check())
```

### 2. Автоматическое исключение нерабочих прокси

Каждый прокси имеет счётчик неудач (`fail_count`). После достижения порога (`max_failures`, по умолчанию 3):
- Прокси помечается как `is_alive = False`
- Исключается из множества проверенных `_checked_proxies`
- Не учитывается при выборе лучшего прокси

```python
controller.config.max_failures = 3  # Порог исключения

# После 3 неудачных проверок прокси автоматически исключается
```

### 3. Измерение задержки (latency)

Каждая успешная проверка измеряет время отклика:
- `proxy.latency` - задержка в миллисекундах
- Рабочие прокси сортируются по задержке (быстрее = лучше)

```python
working_proxies = controller.get_working_proxies()
best_proxy = working_proxies[0]  # Самый быстрый
print(f"Лучший прокси: {best_proxy.host}:{best_proxy.port}")
print(f"Задержка: {best_proxy.latency:.0f}ms")
```

### 4. Периодическая фоновая проверка

При запуске `controller.start()` автоматически:
1. Выполняет начальную асинхронную проверку всех прокси
2. Запускает фоновый асинхронный цикл для периодической проверки
3. Обновляет статус прокси в реальном времени

```python
controller.config.check_interval = 60  # Проверка каждые 60 секунд
controller.start()
```

### 5. Синхронная обёртка для удобства

Для использования в синхронном коде:

```python
from mtproto.controller import run_async_check

results = run_async_check(timeout=5)
```

## API Reference

### Классы

#### `MTProtoProxy`
```python
@dataclass
class MTProtoProxy:
    host: str           # Хост прокси
    port: int           # Порт
    secret: str         # Секретный ключ
    is_alive: bool      # Статус доступности
    latency: float      # Задержка в мс
    fail_count: int     # Счётчик неудач
    last_checked: float # Время последней проверки
```

#### `MTProtoConfig`
```python
@dataclass
class MTProtoConfig:
    enabled: bool = True
    auto_detect: bool = True
    timeout: int = 5              # Таймаут подключения
    retry_count: int = 3          # Попытки переподключения
    check_interval: int = 60      # Интервал проверки (сек)
    max_failures: int = 3         # Порог исключения
    min_working_proxies: int = 5  # Мин. рабочих прокси
```

#### `MTProtoController` - Основные методы

| Метод | Описание |
|-------|----------|
| `check_all_proxies_async()` | Асинхронная проверка всех прокси параллельно |
| `test_proxy_async(proxy)` | Асинхронный тест одного прокси |
| `get_working_proxies()` | Получить рабочие прокси (отсортированы по latency) |
| `find_best_proxy()` | Найти лучший доступный прокси |
| `connect_to_proxy(proxy)` | Подключиться к указанному прокси |
| `get_stats()` | Получить статистику по прокси |
| `reset_failed_proxies()` | Сбросить счётчики неудач |
| `start()` | Запуск с авто-проверкой и мониторингом |
| `stop()` | Остановка |

### Функции модуля

```python
# Асинхронная проверка (требует asyncio)
async def check_proxies_async(log_func=None, timeout: int = 5) -> Dict

# Синхронная обёртка
def run_async_check(timeout: int = 5) -> Dict
```

## Примеры использования

### Пример 1: Быстрая проверка нескольких прокси

```python
from mtproto.controller import MTProtoController, MTProtoProxy
import asyncio

controller = MTProtoController()
controller.config.timeout = 2

# Тестовые прокси
test_proxies = [
    MTProtoProxy("149.154.175.100", 80, "ee0507db..."),
    MTProtoProxy("149.154.175.101", 80, "dd0507db..."),
]

controller.PUBLIC_PROXIES = test_proxies

async def main():
    results = await controller.check_all_proxies_async()
    working = sum(1 for ok in results.values() if ok)
    print(f"Рабочих: {working}/{len(results)}")

asyncio.run(main())
```

### Пример 2: Авто-выбор лучшего прокси

```python
controller = MTProtoController()
controller.start()  # Автоматически проверит и выберет лучший

# Получаем текущий рабочий прокси
current = controller.get_current_proxy()
if current:
    print(f"Подключено к: {current}")
```

### Пример 3: Мониторинг статуса

```python
stats = controller.get_stats()
print(f"Всего: {stats['total']}")
print(f"Рабочих: {stats['working']}")
print(f"Исключено: {stats['failed']}")
print(f"Средняя задержка: {stats['avg_latency']:.0f}ms")
```

### Пример 4: Обработка изменений сети

```python
# При изменении сети (например, переключение WiFi)
controller.reset_failed_proxies()  # Сбросить все счётчики
controller.start()  # Перепроверить все прокси
```

## Архитектура

```
┌─────────────────────────────────────────────────────┐
│              MTProtoController                       │
├─────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌─────────────────────────┐  │
│  │ Async Checker    │  │ Monitor Loop            │  │
│  │ (asyncio event   │  │ (threading.Thread)      │  │
│  │  loop in thread) │  │ - Reconnect logic       │  │
│  │ - Parallel check │  │ - Status monitoring     │  │
│  └──────────────────┘  └─────────────────────────┘  │
│                                                      │
│  ┌──────────────────────────────────────────────┐   │
│  │ Proxy Pool                                   │   │
│  │ - PUBLIC_PROXIES (156 серверов)             │   │
│  │ - Custom proxy_list                          │   │
│  │ - _working_proxies (кэш рабочих)             │   │
│  │ - _checked_proxies (множество проверенных)   │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## Преимущества асинхронного подхода

1. **Производительность**: Проверка 156 прокси занимает ~5-10 секунд вместо ~13 минут при последовательной проверке
2. **Масштабируемость**: Можно легко добавить сотни прокси без потери производительности
3. **Отзывчивость**: GUI не блокируется во время проверки
4. **Автоматизация**: Фоновая проверка постоянно обновляет статус прокси

## Тестирование

Запуск тестов:
```bash
python test_mtproto_async.py
```

Тесты проверяют:
- ✓ Асинхронную проверку прокси
- ✓ Исключение нерабочих прокси
- ✓ Измерение задержки
- ✓ Синхронную обёртку
- ✓ Статистику и мониторинг
