#!/usr/bin/env python3
"""
Анализ данных из памяти после криптографических функций
Данные находятся по адресу 0x10D5C0
"""

import jwt
import struct
import hashlib

# Рабочий токен
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

# Данные из дизассемблера по адресу 0x10D5C0
crypto_data = [
    0xEFFC057FA41007B1, 0x9276D5D9C8B95896,
    0x73201F4C54CC8F9C, 0xD80B579F196F3882,
    0x118B9EC01709304F, 0x5A78EA84BF307F7F,
    0x2FC9E6CA7B9793EA, 0xD30A6CC46EFEB7EA,
    0x697F7D81B8B68AC,  0x14184A147B3EE9F2,
    0xFD6F3064F424C451, 0xAD32AC21B9FE4EB8,
    0x1EBD33FC02CFD678, 0x2B5B694E50021B4
]

# Дополнительные байты
additional_bytes = [0x30, 0x17, 0xA3, 0xD5]
dword_value = 0x5B45B174

def test_key(key):
    """Тестирование ключа"""
    try:
        decoded = jwt.decode(WORKING_TOKEN, key, algorithms=["HS256"])
        print(f"\n✓✓✓ НАЙДЕН КЛЮЧ: {repr(key)}")
        print(f"Тип ключа: {type(key)}")
        if isinstance(key, bytes):
            print(f"Hex: {key.hex()}")
        print(f"Декодированный payload: {decoded}")
        return True
    except:
        return False

def analyze_crypto_data():
    """Анализ криптографических данных"""
    print("=== Анализ данных из памяти 0x10D5C0 ===\n")
    
    keys_to_test = []
    
    # 1. Каждое 64-битное значение как ключ
    print("1. Тестирование 64-битных значений как ключей:")
    for i, val in enumerate(crypto_data):
        # Little-endian
        key_le = struct.pack('<Q', val)
        keys_to_test.append(key_le)
        
        # Big-endian  
        key_be = struct.pack('>Q', val)
        keys_to_test.append(key_be)
        
        # Как строка hex
        hex_str = f"{val:016x}"
        keys_to_test.append(hex_str)
        keys_to_test.append(hex_str.upper())
    
    # 2. Комбинации значений
    print("\n2. Тестирование комбинаций значений:")
    
    # Первые 32 байта (256 бит) - типичный размер для HMAC-SHA256
    first_4_values = crypto_data[:4]
    key_256bit = b''.join(struct.pack('<Q', v) for v in first_4_values)
    keys_to_test.append(key_256bit)
    
    # То же самое в big-endian
    key_256bit_be = b''.join(struct.pack('>Q', v) for v in first_4_values)
    keys_to_test.append(key_256bit_be)
    
    # 3. Дополнительные байты и dword
    print("\n3. Тестирование дополнительных данных:")
    
    # additional_bytes как ключ
    key_additional = bytes(additional_bytes)
    keys_to_test.append(key_additional)
    
    # dword как ключ
    key_dword_le = struct.pack('<I', dword_value)
    keys_to_test.append(key_dword_le)
    key_dword_be = struct.pack('>I', dword_value)
    keys_to_test.append(key_dword_be)
    
    # Комбинация additional_bytes + dword
    key_combined = bytes(additional_bytes) + struct.pack('<I', dword_value)
    keys_to_test.append(key_combined)
    
    # 4. Возможно это таблица для генерации ключа
    print("\n4. Генерация ключей на основе данных:")
    
    # XOR всех значений
    xor_result = 0
    for val in crypto_data:
        xor_result ^= val
    key_xor = struct.pack('<Q', xor_result)
    keys_to_test.append(key_xor)
    
    # Сумма всех значений
    sum_result = sum(crypto_data) & 0xFFFFFFFFFFFFFFFF
    key_sum = struct.pack('<Q', sum_result)
    keys_to_test.append(key_sum)
    
    # MD5/SHA хеши от данных
    all_data = b''.join(struct.pack('<Q', v) for v in crypto_data)
    keys_to_test.append(hashlib.md5(all_data).digest())
    keys_to_test.append(hashlib.sha256(all_data).digest())
    keys_to_test.append(hashlib.sha1(all_data).digest())
    
    # 5. Интерпретация как строки
    print("\n5. Интерпретация как строки:")
    
    # Попробуем декодировать как ASCII/UTF-8
    for val in crypto_data:
        try:
            # 8 байт как строка
            val_bytes = struct.pack('<Q', val)
            # Фильтруем только печатаемые символы
            printable = bytes(b for b in val_bytes if 32 <= b <= 126)
            if len(printable) >= 4:  # Минимум 4 символа
                keys_to_test.append(printable)
                keys_to_test.append(printable.decode('ascii', errors='ignore'))
        except:
            pass
    
    # 6. Специальные комбинации с vehicle_id
    vehicle_id = "0d79ff047f5cec5bf2ec2ec7d3e464ce"
    
    # XOR vehicle_id с первым значением
    vid_bytes = bytes.fromhex(vehicle_id)
    first_val_bytes = struct.pack('<Q', crypto_data[0])
    
    # Расширяем до нужной длины
    xor_key = bytes(a ^ b for a, b in zip(vid_bytes, first_val_bytes * 4))
    keys_to_test.append(xor_key)
    
    # Тестируем все ключи
    print(f"\n\nВсего ключей для тестирования: {len(keys_to_test)}")
    print("Начинаем тестирование...\n")
    
    found = False
    for i, key in enumerate(keys_to_test):
        if i % 50 == 0 and i > 0:
            print(f"  Протестировано {i}/{len(keys_to_test)}...")
        
        if test_key(key):
            found = True
            with open('FOUND_KEY_FROM_CRYPTO_DATA.txt', 'w') as f:
                f.write(f"JWT KEY FOUND!\n")
                f.write(f"Key (repr): {repr(key)}\n")
                if isinstance(key, bytes):
                    f.write(f"Key (hex): {key.hex()}\n")
                f.write(f"Key type: {type(key)}\n")
                f.write(f"Working token: {WORKING_TOKEN}\n")
            break
    
    if not found:
        print("\n✗ Ключ не найден в данных по адресу 0x10D5C0")
        print("\nВозможные объяснения:")
        print("1. Это может быть таблица подстановки для криптографии")
        print("2. Ключ может генерироваться из комбинации этих данных и системной информации")
        print("3. Это могут быть параметры для криптографического алгоритма")
        
        # Выводим данные для анализа
        print("\nДанные для дальнейшего анализа:")
        print("Все значения (hex):")
        for i, val in enumerate(crypto_data):
            print(f"  [{i:2d}]: 0x{val:016X}")
        
        print(f"\nДополнительные байты: {[hex(b) for b in additional_bytes]}")
        print(f"DWORD значение: 0x{dword_value:08X}")

if __name__ == "__main__":
    analyze_crypto_data()
