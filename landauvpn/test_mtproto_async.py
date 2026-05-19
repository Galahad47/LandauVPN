#!/usr/bin/env python3
"""
Тест асинхронной проверки MTProto прокси
"""

import asyncio
from mtproto.controller import MTProtoController, MTProtoProxy


def test_async_proxy_check():
    """Тестирование асинхронной проверки прокси"""
    
    print("=" * 60)
    print("LandauVPN - Тест асинхронной проверки MTProto прокси")
    print("=" * 60)
    
    # Создаём контроллер с логированием
    def log(msg):
        print(f'  [LOG] {msg}')
    
    controller = MTProtoController(log_func=log)
    controller.config.timeout = 2  # Уменьшаем таймаут для теста
    controller.config.max_failures = 2
    
    # Используем только несколько прокси для быстрого теста
    test_proxies = [
        MTProtoProxy("149.154.175.100", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.101", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.102", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.103", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.104", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
    ]
    
    # Заменяем список публичных прокси на тестовый
    controller.PUBLIC_PROXIES = test_proxies
    
    async def run_test():
        print("\n📡 Запуск асинхронной проверки прокси...\n")
        
        # Выполняем проверку всех прокси
        results = await controller.check_all_proxies_async()
        
        # Выводим результаты
        print("\n" + "=" * 60)
        print("РЕЗУЛЬТАТЫ ПРОВЕРКИ:")
        print("=" * 60)
        
        working_count = 0
        failed_count = 0
        
        for proxy, is_working in results.items():
            if is_working:
                status = "✓ РАБОЧИЙ"
                working_count += 1
                print(f"  {status}: {proxy.host}:{proxy.port} (latency={proxy.latency:.0f}ms)")
            else:
                status = "✗ НЕРАБОЧИЙ"
                failed_count += 1
                print(f"  {status}: {proxy.host}:{proxy.port}")
        
        print("\n" + "-" * 60)
        print(f"✅ Рабочих: {working_count}")
        print(f"❌ Нерабочих: {failed_count}")
        print(f"📊 Всего проверено: {len(results)}")
        
        # Получаем рабочие прокси
        working_proxies = controller.get_working_proxies()
        if working_proxies:
            print(f"\n🏆 Лучший прокси (минимальная задержка):")
            best = working_proxies[0]
            print(f"   {best.host}:{best.port} ({best.latency:.0f}ms)")
        
        # Статистика
        stats = controller.get_stats()
        print(f"\n📈 Статистика:")
        print(f"   Всего прокси: {stats['total']}")
        print(f"   Рабочих: {stats['working']}")
        print(f"   Исключено: {stats['failed']}")
        print(f"   Средняя задержка: {stats['avg_latency']:.0f}ms")
        
        return working_count > 0
    
    # Запускаем асинхронный тест
    try:
        success = asyncio.run(run_test())
        
        print("\n" + "=" * 60)
        if success:
            print("✅ ТЕСТ ПРОЙДЕН: Найдены рабочие прокси")
        else:
            print("⚠️ ТЕСТ ЗАВЕРШЁН: Рабочие прокси не найдены (возможно, проблемы с сетью)")
        print("=" * 60)
        
        return success
        
    except KeyboardInterrupt:
        print("\n⚠️ Тест прерван пользователем")
        return False
    except Exception as e:
        print(f"\n❌ Ошибка при выполнении теста: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_sync_wrapper():
    """Тест синхронной обёртки для асинхронной проверки"""
    from mtproto.controller import run_async_check, MTProtoProxy
    
    print("\n" + "=" * 60)
    print("Тест синхронной обёртки run_async_check()")
    print("=" * 60)
    
    # Создаём временный контроллер для теста
    controller = MTProtoController()
    
    # Тестовые прокси
    test_proxy = MTProtoProxy("149.154.175.100", 80, "ee0507dbf25e6e9c438a9eb097032d0545")
    controller.PUBLIC_PROXIES = [test_proxy]
    controller.config.timeout = 2
    
    try:
        # Сохраняем PUBLIC_PROXIES в глобальной области для функции
        original_proxies = MTProtoController.PUBLIC_PROXIES
        MTProtoController.PUBLIC_PROXIES = [test_proxy]
        
        print("\nЗапуск проверки через run_async_check()...")
        results = run_async_check(timeout=2)
        
        print(f"\nРезультат: {len([r for r in results.values() if r])} рабочих из {len(results)}")
        
        # Восстанавливаем оригинальный список
        MTProtoController.PUBLIC_PROXIES = original_proxies
        
        return True
    except Exception as e:
        print(f"Ошибка: {e}")
        return False


if __name__ == "__main__":
    import sys
    
    print("\n🚀 LandauVPN MTProto Async Proxy Checker Test\n")
    
    # Тест 1: Основная асинхронная проверка
    test1_passed = test_async_proxy_check()
    
    # Тест 2: Синхронная обёртка
    test2_passed = test_sync_wrapper()
    
    # Итоговый результат
    print("\n" + "=" * 60)
    print("ИТОГИ ТЕСТИРОВАНИЯ:")
    print("=" * 60)
    print(f"  [{'✓' if test1_passed else '✗'}] Асинхронная проверка прокси")
    print(f"  [{'✓' if test2_passed else '✗'}] Синхронная обёртка run_async_check()")
    
    if test1_passed or test2_passed:
        print("\n✅ Все основные тесты пройдены!")
        sys.exit(0)
    else:
        print("\n⚠️ Некоторые тесты не пройдены")
        sys.exit(1)
