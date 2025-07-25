#!/usr/bin/env python3
"""
ФИНАЛЬНОЕ РЕШЕНИЕ для unlock системы
Использует найденную структуру JWT
"""

import jwt
from datetime import datetime

# ПРИМЕЧАНИЕ: Точный SECRET_KEY не найден статическим анализом
# Но мы знаем рабочую структуру токена

WORKING_TOKEN_EXAMPLE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

def get_unlock_instructions():
    """Инструкции по использованию unlock"""
    print("🔐 ФИНАЛЬНОЕ РЕШЕНИЕ ДЛЯ UNLOCK СИСТЕМЫ")
    print("="*60)
    print()
    print("📋 ЧТО ВЫЯСНЕНО:")
    print("✅ Unlock работает ОФЛАЙН (без интернета)")
    print("✅ Проверяет vehicle_id через getprop")
    print("✅ Читает JWT из системной переменной")
    print("✅ Валидирует соответствие vehicle_id в JWT")
    print("✅ Структура JWT: vehicle_id, iss='CunBA', timestamp")
    print()
    print("🔑 РАБОЧИЙ ТОКЕН (для vehicle_id: 0d79ff047f5cec5bf2ec2ec7d3e464ce):")
    print(WORKING_TOKEN_EXAMPLE)
    print()
    print("🚀 КАК ИСПОЛЬЗОВАТЬ:")
    print("1. Подключитесь к Android устройству:")
    print("   adb shell")
    print("   su")
    print()
    print("2. Установите JWT токен в переменную:")
    print("   setprop persist.cunba 'JWT_TOKEN_HERE'")
    print("   # или")
    print("   setprop persist.jwt 'JWT_TOKEN_HERE'")
    print("   # или экспортируйте как переменную окружения")
    print()
    print("3. Запустите unlock:")
    print("   cd /data/local/tmp")
    print("   ./unlock")
    print()
    print("💡 ЕСЛИ НУЖЕН НОВЫЙ ТОКЕН:")
    print("- Обратитесь к источнику рабочего токена")
    print("- Используйте динамический анализ с Frida")
    print("- Токен может генерироваться на сервере")
    print()
    print("⚠️  ВАЖНО:")
    print("- SECRET_KEY не найден статическим анализом")
    print("- Рекомендуется использовать рабочий токен")
    print("- Для новых vehicle_id нужен правильный ключ")

def decode_working_token():
    """Декодирование рабочего токена"""
    print("\n📊 АНАЛИЗ РАБОЧЕГО ТОКЕНА:")
    print("-"*40)
    
    decoded = jwt.decode(WORKING_TOKEN_EXAMPLE, options={"verify_signature": False})
    header = jwt.get_unverified_header(WORKING_TOKEN_EXAMPLE)
    
    print(f"Header: {header}")
    print(f"Payload: {decoded}")
    
    if 'timestamp' in decoded:
        ts = decoded['timestamp']
        dt = datetime.fromtimestamp(ts)
        print(f"Создан: {dt.strftime('%Y-%m-%d %H:%M:%S')}")

def verify_token_structure(vehicle_id, token):
    """Проверка структуры токена"""
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        
        # Проверяем обязательные поля
        required_fields = ['vehicle_id', 'iss', 'timestamp']
        for field in required_fields:
            if field not in decoded:
                return False, f"Отсутствует поле: {field}"
        
        # Проверяем значения
        if decoded['iss'] != 'CunBA':
            return False, f"Неправильный iss: {decoded['iss']}"
        
        if decoded['vehicle_id'] != vehicle_id:
            return False, f"Неправильный vehicle_id: {decoded['vehicle_id']}"
        
        return True, "Структура токена корректна"
        
    except Exception as e:
        return False, f"Ошибка декодирования: {e}"

def main():
    """Главная функция"""
    get_unlock_instructions()
    decode_working_token()
    
    print(f"\n🎯 ПРОВЕРКА ТОКЕНА:")
    print("-"*30)
    vehicle_id = "0d79ff047f5cec5bf2ec2ec7d3e464ce"
    is_valid, message = verify_token_structure(vehicle_id, WORKING_TOKEN_EXAMPLE)
    print(f"Результат: {'✅' if is_valid else '❌'} {message}")
    
    print(f"\n💾 СОХРАНЕНИЕ РАБОЧЕГО ТОКЕНА:")
    print("-"*35)
    with open("working_token.txt", "w") as f:
        f.write(WORKING_TOKEN_EXAMPLE)
    print("✅ Токен сохранен в working_token.txt")

if __name__ == "__main__":
    main()
