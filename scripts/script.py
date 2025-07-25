# jwt_generator_exp.py
import jwt
import time
import sys
from datetime import datetime, timedelta

# ПРАВИЛЬНЫЙ СЕКРЕТНЫЙ КЛЮЧ (найден анализом бинарника)
SECRET_KEY = "sssss3issssssmossssssmssssss/dssssssisssss"

def generate_jwt_with_exp(vehicle_id):
    try:
        current_time = datetime.now()
        # Устанавливаем время жизни токена - 5 минут с текущего момента
        expiration_time = current_time + timedelta(minutes=5)
        
        payload = {
            "vehicle_id": vehicle_id,
            "iss": "CunBA",
            "timestamp": int(current_time.timestamp()),
            "exp": int(expiration_time.timestamp()) # <<<--- ВОТ ВАЖНОЕ ПОЛЕ
        }
        print(f"[*] Создаем payload с временем жизни до {expiration_time.strftime('%H:%M:%S')}")
        
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return token
    except Exception as e:
        print(f"Ошибка: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) > 1:
        vehicle_id_input = sys.argv[1]
    else:
        vehicle_id_input = input("Введите vehicle_id: ")

    if vehicle_id_input:
        generated_token = generate_jwt_with_exp(vehicle_id_input)
        if generated_token:
            print("\n✅ Готовый JWT Токен с полем 'exp':")
            print("="*80)
            print(generated_token)
            print("="*80)