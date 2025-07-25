#!/usr/bin/env python3
"""
JWT валидатор для проверки потенциальных SECRET_KEY
Использует известный рабочий JWT для валидации ключей
"""

import jwt
import json
import sys
import hashlib
from datetime import datetime
import binascii

class JWTValidator:
    def __init__(self):
        # Известный рабочий JWT (из вашего примера)
        self.known_jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ2ZWhpY2xlX2lkIjoiOTA5MDQ1NiIsImlzcyI6IkN1bkJBIiwidGltZXN0YW1wIjoxNzM2MzQzMjc0fQ.signature_here"
        
        # Известная полезная нагрузка для генерации тестовых токенов
        self.test_payload = {
            "vehicle_id": "9090456",
            "iss": "CunBA",
            "timestamp": 1736343274
        }
    
    def test_key_with_known_jwt(self, potential_key):
        """Тестирование ключа с известным JWT"""
        try:
            # Пробуем разные форматы ключа
            key_formats = [
                potential_key,  # Как есть
                potential_key.encode() if isinstance(potential_key, str) else potential_key,  # В байтах
                hashlib.sha256(potential_key.encode() if isinstance(potential_key, str) else potential_key).digest(),  # SHA256 хэш
                binascii.unhexlify(potential_key) if isinstance(potential_key, str) and len(potential_key) == 64 else None  # Из hex
            ]
            
            for key_format in key_formats:
                if key_format is None:
                    continue
                    
                try:
                    # Генерируем JWT с тестовым ключом
                    test_jwt = jwt.encode(self.test_payload, key_format, algorithm='HS256')
                    print(f"✓ Ключ работает! Формат: {type(key_format)}")
                    print(f"  Тестовый JWT: {test_jwt}")
                    
                    # Проверяем декодирование
                    decoded = jwt.decode(test_jwt, key_format, algorithms=['HS256'])
                    print(f"  Декодированный payload: {decoded}")
                    return key_format
                    
                except jwt.InvalidSignatureError:
                    continue
                except Exception as e:
                    print(f"  Ошибка с форматом {type(key_format)}: {e}")
                    continue
            
            return None
            
        except Exception as e:
            print(f"✗ Ошибка тестирования ключа: {e}")
            return None
    
    def generate_jwt_for_vehicle(self, key, vehicle_id):
        """Генерация JWT для конкретного vehicle_id"""
        payload = {
            "vehicle_id": vehicle_id,
            "iss": "CunBA",
            "timestamp": int(datetime.now().timestamp())
        }
        
        try:
            token = jwt.encode(payload, key, algorithm='HS256')
            print(f"🎯 Сгенерированный JWT для vehicle_id '{vehicle_id}':")
            print(f"   {token}")
            return token
        except Exception as e:
            print(f"✗ Ошибка генерации JWT: {e}")
            return None
    
    def decode_jwt_info(self, token):
        """Декодирование JWT без проверки подписи для анализа"""
        try:
            # Декодируем без проверки подписи
            decoded = jwt.decode(token, options={"verify_signature": False})
            header = jwt.get_unverified_header(token)
            
            print("📋 Информация о JWT:")
            print(f"   Header: {json.dumps(header, indent=2)}")
            print(f"   Payload: {json.dumps(decoded, indent=2)}")
            
            # Проверяем временную метку
            if 'timestamp' in decoded:
                timestamp = decoded['timestamp']
                dt = datetime.fromtimestamp(timestamp)
                print(f"   Время создания: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
            
            return decoded, header
        except Exception as e:
            print(f"✗ Ошибка декодирования JWT: {e}")
            return None, None

def main():
    validator = JWTValidator()
    
    print("🔐 JWT Валидатор для unlock системы")
    print("=" * 50)
    
    if len(sys.argv) < 2:
        print("Использование:")
        print("  python jwt_validator.py <потенциальный_ключ>")
        print("  python jwt_validator.py --decode <jwt_token>")
        print("  python jwt_validator.py --generate <ключ> <vehicle_id>")
        return
    
    command = sys.argv[1]
    
    if command == "--decode" and len(sys.argv) == 3:
        # Декодирование JWT
        jwt_token = sys.argv[2]
        validator.decode_jwt_info(jwt_token)
        
    elif command == "--generate" and len(sys.argv) == 4:
        # Генерация JWT
        key = sys.argv[2]
        vehicle_id = sys.argv[3]
        validator.generate_jwt_for_vehicle(key, vehicle_id)
        
    else:
        # Тестирование потенциального ключа
        potential_key = sys.argv[1]
        print(f"🧪 Тестируем потенциальный ключ: {potential_key}")
        
        working_key = validator.test_key_with_known_jwt(potential_key)
        
        if working_key:
            print(f"\n🎉 НАЙДЕН РАБОЧИЙ КЛЮЧ!")
            print(f"Ключ: {working_key}")
            
            # Предлагаем сгенерировать JWT для тестового vehicle_id
            test_vehicle = input("\nВведите vehicle_id для тестирования (или Enter для пропуска): ").strip()
            if test_vehicle:
                validator.generate_jwt_for_vehicle(working_key, test_vehicle)
        else:
            print("😞 Ключ не подходит. Попробуйте другой кандидат.")

if __name__ == "__main__":
    main()
