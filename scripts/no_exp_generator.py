#!/usr/bin/env python3
"""
Генератор JWT токенов БЕЗ поля exp (как у рабочего токена)
"""

import jwt
from datetime import datetime

# Ключ найденный из анализа бинарника
SECRET_KEY = "sssss3issssssmossssssmssssss/dssssssisssss"

def generate_token_no_exp(vehicle_id):
    """Генерация токена БЕЗ поля exp (как у рабочего)"""
    payload = {
        "vehicle_id": vehicle_id,
        "iss": "CunBA",
        "timestamp": int(datetime.now().timestamp())
    }
    
    try:
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return token
    except Exception as e:
        print(f"Ошибка: {e}")
        return None

def generate_token_with_exact_timestamp(vehicle_id, timestamp):
    """Генерация токена с точной временной меткой"""
    payload = {
        "vehicle_id": vehicle_id,
        "iss": "CunBA", 
        "timestamp": timestamp
    }
    
    try:
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return token
    except Exception as e:
        print(f"Ошибка: {e}")
        return None

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        vehicle_id = sys.argv[1]
    else:
        vehicle_id = input("Введите vehicle_id: ")
    
    print("🔧 Генерация JWT БЕЗ поля exp:")
    print("="*50)
    
    # Токен без exp
    token_no_exp = generate_token_no_exp(vehicle_id)
    if token_no_exp:
        print("✅ JWT токен БЕЗ поля exp:")
        print("="*80)
        print(token_no_exp)
        print("="*80)
    
    # Попробуем воспроизвести точную временную метку рабочего токена
    print(f"\n🎯 Попытка воспроизвести с timestamp рабочего токена (1753096202):")
    token_exact = generate_token_with_exact_timestamp(vehicle_id, 1753096202)
    if token_exact:
        print("="*80)
        print(token_exact)
        print("="*80)
        
        # Сравниваем с рабочим токеном
        working_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"
        if token_exact == working_token:
            print("🎉 ИДЕНТИЧЕН рабочему токену!")
        else:
            print("⚠️  Отличается от рабочего токена")
            print(f"Рабочий: {working_token}")
            print(f"Наш:     {token_exact}")
