#!/bin/bash
# Скрипт сборки LandauVPN в исполняемый файл

set -e

echo "🔨 Сборка LandauVPN..."

# Установка зависимостей
echo "📦 Установка зависимостей..."
pip install -q customtkinter requests pyinstaller

# Очистка предыдущих сборок
echo "🧹 Очистка..."
rm -rf build dist __pycache__

# Сборка через PyInstaller
echo "🏗️  Сборка executable файла..."
pyinstaller landauvpn.spec --clean

# Проверка результата
if [ -f "dist/LandauVPN" ]; then
    echo "✅ Сборка завершена успешно!"
    echo "📍 Исполняемый файл: $(pwd)/dist/LandauVPN"
    ls -lh dist/LandauVPN
else
    echo "❌ Ошибка сборки!"
    exit 1
fi
