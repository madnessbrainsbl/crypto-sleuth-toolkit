#!/usr/bin/env python3
"""
Сравнение рабочего и нерабочего токенов для поиска ключевых различий
"""
import jwt
import json
import base64

# 100% рабочий токен (работает и делает Success + перезагрузка)
working_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

# Нерабочий токен (с полем exp)
broken_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5Njc2MSwiZXhwIjoxNzUzMDk3MDYxfQ.StCOSqg0VcOs3UTTOfYsq1JWitZ9bLL9gTepJD8LMuY"

print("🔍 АНАЛИЗ ТОКЕНОВ")
print("="*60)

# Декодируем заголовки
working_header = jwt.get_unverified_header(working_token)
broken_header = jwt.get_unverified_header(broken_token)

print("\n📋 ЗАГОЛОВКИ:")
print(f"Рабочий: {working_header}")
print(f"Нерабочий: {broken_header}")
print(f"Заголовки идентичны: {working_header == broken_header}")

# Декодируем payload
working_payload = jwt.decode(working_token, options={"verify_signature": False})
broken_payload = jwt.decode(broken_token, options={"verify_signature": False})

print("\n📦 PAYLOAD:")
print("Рабочий токен:")
for key, value in working_payload.items():
    print(f"  {key}: {value}")

print("\nНерабочий токен:")
for key, value in broken_payload.items():
    print(f"  {key}: {value}")

# Находим различия
print("\n🔍 РАЗЛИЧИЯ:")
working_keys = set(working_payload.keys())
broken_keys = set(broken_payload.keys())

print(f"Только в рабочем: {working_keys - broken_keys}")
print(f"Только в нерабочем: {broken_keys - working_keys}")

# Проверяем общие поля
common_keys = working_keys & broken_keys
for key in common_keys:
    if working_payload[key] != broken_payload[key]:
        print(f"Различие в '{key}': {working_payload[key]} vs {broken_payload[key]}")

print("\n🎯 КЛЮЧЕВЫЕ ВЫВОДЫ:")
print("✅ Рабочий токен НЕ содержит поле 'exp' (время истечения)")
print("❌ Нерабочий токен содержит поле 'exp'")
print("💡 Система отклоняет токены с полем exp!")

print("\n📊 АНАЛИЗ ПОДПИСЕЙ:")
working_parts = working_token.split('.')
broken_parts = broken_token.split('.')

print(f"Рабочая подпись: {working_parts[2]}")
print(f"Нерабочая подпись: {broken_parts[2]}")
print(f"Подписи разные: {working_parts[2] != broken_parts[2]}")

# Декодируем подписи
try:
    working_sig = base64.urlsafe_b64decode(working_parts[2] + '==')
    broken_sig = base64.urlsafe_b64decode(broken_parts[2] + '==')
    
    print(f"\nРабочая подпись (hex): {working_sig.hex()}")
    print(f"Нерабочая подпись (hex): {broken_sig.hex()}")
    print(f"Длина подписи: {len(working_sig)} байт")
except Exception as e:
    print(f"Ошибка декодирования подписи: {e}")

print("\n🚀 СЛЕДУЮЩИЕ ШАГИ:")
print("1. Генерировать токены БЕЗ поля 'exp'")
print("2. Использовать точно такую же структуру как в рабочем токене")
print("3. Искать ключ для подписи HMAC-SHA256")

# Создаем точную копию payload для тестирования ключей
exact_payload = {
    "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
    "iss": "CunBA", 
    "timestamp": 1753096202
}

print(f"\n🎯 ТОЧНЫЙ PAYLOAD ДЛЯ ТЕСТИРОВАНИЯ:")
print(json.dumps(exact_payload, separators=(',', ':')))
