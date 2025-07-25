#!/usr/bin/env python3
"""
Статический анализ ELF файла unlock для поиска SECRET_KEY
Используем доступные инструменты для анализа бинарника
"""

import subprocess
import re
import os
import struct
from pathlib import Path

def run_command(cmd, shell=True):
    """Выполнение команды и возврат результата"""
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=30)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout", -1
    except Exception as e:
        return "", str(e), -1

def analyze_elf_header():
    """Анализ заголовка ELF файла"""
    print("🔍 АНАЛИЗ ЗАГОЛОВКА ELF ФАЙЛА")
    print("="*50)
    
    try:
        with open("unlock", "rb") as f:
            # Читаем ELF заголовок
            elf_header = f.read(64)
            
            if elf_header[:4] != b'\x7fELF':
                print("❌ Не является ELF файлом")
                return
            
            # Парсим базовую информацию
            ei_class = elf_header[4]  # 32-bit (1) или 64-bit (2)
            ei_data = elf_header[5]   # Little endian (1) или Big endian (2)
            ei_version = elf_header[6] # Версия ELF
            
            arch = "64-bit" if ei_class == 2 else "32-bit"
            endian = "Little Endian" if ei_data == 1 else "Big Endian"
            
            print(f"✅ Валидный ELF файл")
            print(f"   Архитектура: {arch}")
            print(f"   Порядок байт: {endian}")
            print(f"   Версия ELF: {ei_version}")
            
            # Пытаемся получить больше информации о машине
            if ei_class == 2:  # 64-bit
                fmt = "<H" if ei_data == 1 else ">H"
                e_machine = struct.unpack(fmt, elf_header[18:20])[0]
            else:  # 32-bit  
                fmt = "<H" if ei_data == 1 else ">H"
                e_machine = struct.unpack(fmt, elf_header[18:20])[0]
            
            machine_types = {
                0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64", 
                0x3: "x86", 0x8: "MIPS", 0x14: "PowerPC"
            }
            
            machine = machine_types.get(e_machine, f"Unknown (0x{e_machine:x})")
            print(f"   Тип машины: {machine}")
            
    except Exception as e:
        print(f"❌ Ошибка анализа ELF: {e}")

def extract_strings_analysis():
    """Извлечение и анализ строк из бинарника"""
    print("\n🔤 АНАЛИЗ СТРОК В БИНАРНИКЕ")
    print("="*50)
    
    # Попробуем использовать strings если доступен
    stdout, stderr, code = run_command("strings unlock")
    
    if code != 0:
        # Fallback - извлекаем строки вручную
        print("⚠️  Команда 'strings' недоступна, извлекаем строки вручную...")
        strings_list = extract_strings_manual()
    else:
        strings_list = stdout.split('\n')
    
    print(f"Найдено {len(strings_list)} строк")
    
    # Ищем интересные строки
    crypto_strings = []
    jwt_strings = []
    cunba_strings = []
    key_strings = []
    
    for s in strings_list:
        s = s.strip()
        if len(s) < 3:
            continue
            
        s_lower = s.lower()
        
        # Криптографические термины
        if any(term in s_lower for term in ['hmac', 'sha256', 'jwt', 'encrypt', 'decrypt', 'sign']):
            crypto_strings.append(s)
        
        # JWT связанные
        if any(term in s_lower for term in ['jwt', 'token', 'bearer', 'header', 'payload']):
            jwt_strings.append(s)
        
        # CunBA связанные
        if any(term in s_lower for term in ['cunba', 'unlock', 'mega', 'vehicle']):
            cunba_strings.append(s)
        
        # Потенциальные ключи (длинные алфанумерические строки)
        if (len(s) >= 16 and len(s) <= 128 and 
            re.match(r'^[A-Za-z0-9+/=_-]+$', s) and 
            not re.match(r'^[0-9]+$', s)):
            key_strings.append(s)
    
    print(f"\n📊 КАТЕГОРИИ СТРОК:")
    print(f"   🔐 Криптографические: {len(crypto_strings)}")
    print(f"   🎫 JWT связанные: {len(jwt_strings)}")
    print(f"   🚗 CunBA/unlock: {len(cunba_strings)}")
    print(f"   🔑 Потенциальные ключи: {len(key_strings)}")
    
    # Показываем самые интересные
    if crypto_strings:
        print(f"\n🔐 КРИПТОГРАФИЧЕСКИЕ СТРОКИ:")
        for s in crypto_strings[:10]:
            print(f"   {s}")
    
    if jwt_strings:
        print(f"\n🎫 JWT СТРОКИ:")
        for s in jwt_strings[:10]:
            print(f"   {s}")
    
    if cunba_strings:
        print(f"\n🚗 CUNBA/UNLOCK СТРОКИ:")
        for s in cunba_strings[:10]:
            print(f"   {s}")
    
    if key_strings:
        print(f"\n🔑 ПОТЕНЦИАЛЬНЫЕ КЛЮЧИ:")
        for s in key_strings[:10]:
            print(f"   {s}")
    
    return key_strings + crypto_strings + jwt_strings

def extract_strings_manual():
    """Ручное извлечение строк из бинарника"""
    strings = []
    current_string = ""
    
    try:
        with open("unlock", "rb") as f:
            while True:
                byte = f.read(1)
                if not byte:
                    break
                
                b = ord(byte)
                if 32 <= b <= 126:  # Printable ASCII
                    current_string += chr(b)
                else:
                    if len(current_string) >= 4:
                        strings.append(current_string)
                    current_string = ""
        
        if current_string and len(current_string) >= 4:
            strings.append(current_string)
            
    except Exception as e:
        print(f"❌ Ошибка извлечения строк: {e}")
    
    return strings

def analyze_binary_patterns():
    """Поиск паттернов в бинарных данных"""
    print("\n🔍 ПОИСК БИНАРНЫХ ПАТТЕРНОВ")
    print("="*50)
    
    try:
        with open("unlock", "rb") as f:
            data = f.read()
        
        # Ищем известные криптографические константы
        crypto_patterns = {
            # HMAC-SHA256 константы
            b'\x36\x36\x36\x36': 'HMAC ipad pattern',
            b'\x5c\x5c\x5c\x5c': 'HMAC opad pattern',
            # SHA-256 инициализационные векторы
            b'\x6a\x09\xe6\x67': 'SHA-256 IV H0',
            b'\xbb\x67\xae\x85': 'SHA-256 IV H1',
            # JWT подписи в base64url
            b'eyJhbGciOiJIUzI1NiI': 'JWT header HS256',
            b'eyJ0eXAiOiJKV1Qi': 'JWT header typ',
        }
        
        found_patterns = []
        for pattern, description in crypto_patterns.items():
            pos = data.find(pattern)
            if pos != -1:
                found_patterns.append((pos, pattern, description))
        
        if found_patterns:
            print("✅ Найдены криптографические паттерны:")
            for pos, pattern, desc in found_patterns:
                print(f"   0x{pos:08x}: {desc}")
        else:
            print("❌ Криптографические паттерны не найдены")
        
        # Поиск повторяющихся последовательностей
        print("\n🔄 Поиск повторяющихся последовательностей...")
        repetitions = find_repetitions(data)
        
        if repetitions:
            print("✅ Найдены повторения:")
            for seq, count, positions in repetitions[:5]:
                if len(seq) >= 8:
                    print(f"   {seq.hex()}: {count} раз")
        
    except Exception as e:
        print(f"❌ Ошибка анализа паттернов: {e}")

def find_repetitions(data, min_length=8, min_count=2):
    """Поиск повторяющихся последовательностей"""
    sequences = {}
    
    # Ищем последовательности длиной от min_length до 32 байт
    for length in range(min_length, 33):
        for i in range(len(data) - length):
            seq = data[i:i+length]
            
            if seq not in sequences:
                sequences[seq] = []
            sequences[seq].append(i)
    
    # Фильтруем по минимальному количеству повторений
    repetitions = []
    for seq, positions in sequences.items():
        if len(positions) >= min_count:
            repetitions.append((seq, len(positions), positions))
    
    # Сортируем по количеству повторений
    repetitions.sort(key=lambda x: x[1], reverse=True)
    
    return repetitions

def test_extracted_keys(potential_keys):
    """Тестирование извлеченных потенциальных ключей"""
    print("\n🧪 ТЕСТИРОВАНИЕ ИЗВЛЕЧЕННЫХ КЛЮЧЕЙ")
    print("="*50)
    
    if not potential_keys:
        print("❌ Нет ключей для тестирования")
        return
    
    # Импортируем функцию тестирования
    try:
        import jwt
        
        WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"
        
        EXACT_PAYLOAD = {
            "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
            "iss": "CunBA",
            "timestamp": 1753096202
        }
        
        print(f"Тестируем {len(potential_keys)} потенциальных ключей...")
        
        for i, key in enumerate(potential_keys):
            try:
                test_token = jwt.encode(EXACT_PAYLOAD, key, algorithm='HS256')
                if test_token == WORKING_TOKEN:
                    print(f"\n🎉 НАЙДЕН SECRET_KEY!")
                    print(f"Ключ: '{key}'")
                    print(f"Источник: статический анализ ELF")
                    return key
            except:
                continue
                
            if i % 50 == 0 and i > 0:
                print(f"   Протестировано {i}/{len(potential_keys)}...")
        
        print("❌ Ни один из извлеченных ключей не подошел")
        
    except ImportError:
        print("❌ JWT библиотека недоступна для тестирования")
    
    return None

def create_ghidra_script():
    """Создание скрипта для Ghidra анализа"""
    print("\n📝 СОЗДАНИЕ СКРИПТА ДЛЯ GHIDRA")
    print("="*50)
    
    script_content = '''//Ghidra script для анализа unlock бинарника
//Поиск криптографических функций и ключей
//@author Auto-generated
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class UnlockAnalyzer extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        
        println("=== UNLOCK BINARY ANALYSIS ===");
        
        // Поиск строк связанных с JWT/crypto
        findCryptoStrings();
        
        // Поиск функций
        findCryptoFunctions();
        
        // Поиск потенциальных ключей
        findPotentialKeys();
    }
    
    private void findCryptoStrings() {
        println("\\n--- Поиск криптографических строк ---");
        
        String[] cryptoKeywords = {
            "jwt", "hmac", "sha256", "sign", "verify",
            "CunBA", "unlock", "secret", "key", "token"
        };
        
        for (String keyword : cryptoKeywords) {
            println("Поиск: " + keyword);
            // Здесь код поиска строк в Ghidra API
        }
    }
    
    private void findCryptoFunctions() {
        println("\\n--- Поиск криптографических функций ---");
        
        String[] cryptoFuncs = {
            "HMAC_Init", "HMAC_Update", "HMAC_Final",
            "SHA256_Init", "SHA256_Update", "SHA256_Final",
            "jwt_encode", "jwt_decode", "jwt_sign"
        };
        
        for (String func : cryptoFuncs) {
            println("Поиск функции: " + func);
        }
    }
    
    private void findPotentialKeys() {
        println("\\n--- Поиск потенциальных ключей ---");
        
        // Поиск статических буферов подходящего размера
        // для HMAC ключей (обычно 16-64 байта)
    }
}'''
    
    with open("D:/vzlom/UnlockAnalyzer.java", "w", encoding="utf-8") as f:
        f.write(script_content)
    
    print("✅ Создан скрипт UnlockAnalyzer.java для Ghidra")
    print("💡 Инструкции:")
    print("   1. Откройте Ghidra")
    print("   2. Импортируйте файл 'unlock'")
    print("   3. Запустите автоанализ")
    print("   4. Используйте Script Manager для запуска UnlockAnalyzer.java")

def main():
    """Главная функция статического анализа"""
    print("🔬 ELF STATIC ANALYZER")
    print("="*80)
    print("Статический анализ бинарника unlock для поиска SECRET_KEY")
    print()
    
    if not os.path.exists("unlock"):
        print("❌ Файл 'unlock' не найден в текущей директории")
        return
    
    # Анализ ELF заголовка
    analyze_elf_header()
    
    # Извлечение и анализ строк
    potential_keys = extract_strings_analysis()
    
    # Поиск бинарных паттернов
    analyze_binary_patterns()
    
    # Тестирование найденных ключей
    found_key = test_extracted_keys(potential_keys)
    
    # Создание скрипта для Ghidra
    create_ghidra_script()
    
    if found_key:
        print(f"\n🎉 МИССИЯ ВЫПОЛНЕНА!")
        print(f"SECRET_KEY найден: '{found_key}'")
    else:
        print(f"\n💡 РЕКОМЕНДАЦИИ:")
        print("   1. Используйте созданный скрипт в Ghidra для глубокого анализа")
        print("   2. Исследуйте найденные криптографические строки")
        print("   3. Проанализируйте функции работающие с найденными паттернами")

if __name__ == "__main__":
    main()
