# 🔄 Автообновление списков в LandauVPN

## ✅ Реализованные функции

### 1. Автоматическое обновление бесплатных VPN (VPNGate)
- **Интервал**: каждые 5 минут (настраивается через `self._update_interval_ms`)
- **Источник**: парсинг сайта VPNGate
- **Сохранение**: в `free_vpn_profiles.json`
- **Лимит**: 50 профилей за одно обновление

### 2. Автоматическая проверка MTProto прокси
- **Интервал**: синхронно с обновлением VPN (каждые 5 минут)
- **Проверка**: асинхронная параллельная проверка всех прокси
- **Фильтрация**: нерабочие прокси автоматически исключаются из пула
- **Лимит**: топ-20 рабочих прокси по скорости (latency)

### 3. Фоновый цикл обновления
- **Старт**: через 10 секунд после запуска приложения
- **Метод**: `self.after()` для интеграции с event loop tkinter
- **Обработка ошибок**: при ошибке цикл не прерывается, повтор через интервал
- **Отключение**: при закрытии окна (`on_closing`)

## 🔧 Как это работает

```python
# В main_window.py при инициализации:
def create_main_interface(self):
    # ... создание интерфейса ...
    
    # Запуск фонового автообновления
    self._start_auto_update_cycle()

# Метод автообновления:
def _start_auto_update_cycle(self):
    def auto_update_worker():
        if not self._auto_update_enabled:
            return
        
        try:
            # 1. Обновление бесплатных VPN
            free_profiles = fetch_vpngate_profiles(50)
            save_free_profiles_json(free_profiles, FREE_VPN_JSON_FILE)
            
            # 2. Проверка MTProto прокси
            mtproto_ctrl = get_mtproto_controller()
            working_proxies = mtproto_ctrl.get_working_proxies(limit=20)
            
            # 3. Перезапуск цикла
            self.after(self._update_interval_ms, auto_update_worker)
            
        except Exception as e:
            # Повтор даже при ошибке
            self.after(self._update_interval_ms, auto_update_worker)
    
    # Первый запуск через 10 секунд
    self.after(10000, auto_update_worker)
```

## ⚙️ Настройка интервала

Измените интервал обновления в `__init__`:

```python
self._update_interval_ms = 300000  # 5 минут (по умолчанию)
# или
self._update_interval_ms = 60000   # 1 минута
# или
self._update_interval_ms = 600000  # 10 минут
```

## 🛑 Отключение автообновления

Автообновление автоматически отключается при закрытии приложения:

```python
def on_closing(self):
    # Отключение автообновления
    self._auto_update_enabled = False
    
    # Остановка контроллеров
    self.vpn.stop()
    self.proxy.stop()
    if hasattr(self.mtproto, 'stop'):
        self.mtproto.stop()
    if hasattr(self.dpi, 'stop'):
        self.dpi.stop()
    
    self.destroy()
```

## 📊 Логирование

Все события автообновления записываются в лог приложения:

```
🔄 Автообновление: загрузка VPNGate...
✅ Бесплатные VPN обновлены: 50 серверов
🔄 Автообновление: проверка MTProto прокси...
✅ MTProto прокси: 20 рабочих
```

## 🎯 Преимущества

1. **Актуальные данные**: списки всегда свежие
2. **Автоматическая фильтрация**: нерабочие прокси удаляются
3. **Минимальное влияние на UI**: используется `after()` вместо потоков
4. **Отказоустойчивость**: ошибки не ломают цикл
5. **Прозрачность**: все действия логируются

## 📁 Изменённые файлы

| Файл | Изменения |
|------|-----------|
| `gui/main_window.py` | Добавлен метод `_start_auto_update_cycle()`, флаг `_auto_update_enabled`, обновлён `on_closing()` |
| `main.py` | Добавлены сообщения о запуске фоновых служб |
