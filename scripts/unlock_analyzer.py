#!/usr/bin/env python3
"""
Анализатор ELF-бинарника unlock для извлечения SECRET_KEY
Статический анализ строк и паттернов
"""

import re
import sys
import binascii
import struct
from pathlib import Path

class UnlockAnalyzer:
    def __init__(self, binary_path):
        self.binary_path = Path(binary_path)
        self.binary_data = None
        self.potential_keys = []
        self.jwt_patterns = []
        
    def load_binary(self):
        """Загрузка бинарного файла"""
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
            print(f"✓ Загружен файл: {self.binary_path.name} ({len(self.binary_data)} байт)")
            return True
        except Exception as e:
            print(f"✗ Ошибка загрузки файла: {e}")
            return False
    
    def search_strings(self, min_length=4):
        """Поиск ASCII строк в бинарнике"""
        if not self.binary_data:
            return []
            
        # Регулярное выражение для поиска ASCII строк
        pattern = rb'[!-~]{' + str(min_length).encode() + rb',}'
        strings = re.findall(pattern, self.binary_data)
        return [s.decode('ascii', errors='ignore') for s in strings]
    
    def find_jwt_related_strings(self):
        """Поиск строк, связанных с JWT"""
        strings = self.search_strings()
        jwt_keywords = [
            'SECRET_KEY', 'secret', 'key', 'SECRET', 'jwt', 'JWT',
            'CunBA', 'HS256', 'HMAC', 'token', 'authorization',
            'vehicle_id', 'timestamp', 'iss', 'issuer'
        ]
        
        relevant_strings = []
        for string in strings:
            for keyword in jwt_keywords:
                if keyword.lower() in string.lower():
                    relevant_strings.append(string)
                    break
        
        return list(set(relevant_strings))
    
    def search_hex_patterns(self):
        """Поиск потенциальных ключей в hex формате"""
        patterns = []
        
        # Поиск 32-байтных последовательностей (256-bit keys)
        for i in range(0, len(self.binary_data) - 32, 4):
            chunk = self.binary_data[i:i+32]
            # Проверяем, что данные не являются нулями или повторяющимся паттерном
            if len(set(chunk)) > 4:  # Минимальная энтропия
                patterns.append({
                    'offset': hex(i),
                    'data': binascii.hexlify(chunk).decode(),
                    'ascii': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                })
        
        return patterns[:20]  # Возвращаем первые 20 кандидатов
    
    def find_cunba_references(self):
        """Поиск ссылок на 'CunBA' и окружающих данных"""
        cunba_positions = []
        cunba_bytes = b'CunBA'
        
        pos = 0
        while True:
            pos = self.binary_data.find(cunba_bytes, pos)
            if pos == -1:
                break
            
            # Извлекаем контекст вокруг найденной строки
            start = max(0, pos - 64)
            end = min(len(self.binary_data), pos + 64)
            context = self.binary_data[start:end]
            
            cunba_positions.append({
                'offset': hex(pos),
                'context_hex': binascii.hexlify(context).decode(),
                'context_ascii': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in context)
            })
            pos += 1
        
        return cunba_positions
    
    def analyze_elf_sections(self):
        """Базовый анализ ELF секций"""
        if not self.binary_data or len(self.binary_data) < 64:
            return None
        
        # Проверяем ELF магическое число
        if self.binary_data[:4] != b'\x7fELF':
            print("⚠ Файл не является корректным ELF")
            return None
        
        # Читаем ELF header
        elf_class = self.binary_data[4]  # 1=32bit, 2=64bit
        endianness = self.binary_data[5]  # 1=little, 2=big
        
        print(f"✓ ELF {64 if elf_class == 2 else 32}-bit, {'little' if endianness == 1 else 'big'} endian")
        
        return {
            'class': elf_class,
            'endianness': endianness
        }
    
    def run_analysis(self):
        """Запуск полного анализа"""
        print("🔍 Начинаем анализ unlock бинарника...")
        print("=" * 60)
        
        if not self.load_binary():
            return
        
        # 1. Анализ ELF структуры
        print("\n📋 1. Анализ ELF структуры:")
        elf_info = self.analyze_elf_sections()
        
        # 2. Поиск JWT-связанных строк
        print("\n🔤 2. Поиск JWT-связанных строк:")
        jwt_strings = self.find_jwt_related_strings()
        for string in jwt_strings[:10]:  # Показываем первые 10
            print(f"   • {string}")
        if len(jwt_strings) > 10:
            print(f"   ... и еще {len(jwt_strings) - 10} строк")
        
        # 3. Поиск ссылок на CunBA
        print("\n🎯 3. Поиск ссылок на 'CunBA':")
        cunba_refs = self.find_cunba_references()
        for ref in cunba_refs:
            print(f"   Смещение: {ref['offset']}")
            print(f"   ASCII: {ref['context_ascii'][:50]}...")
            print(f"   HEX: {ref['context_hex'][:100]}...")
            print()
        
        # 4. Поиск потенциальных ключей
        print("\n🔑 4. Поиск потенциальных SECRET_KEY (32-байт последовательности):")
        hex_patterns = self.search_hex_patterns()
        for i, pattern in enumerate(hex_patterns[:5]):  # Показываем первые 5
            print(f"   Кандидат {i+1} (смещение {pattern['offset']}):")
            print(f"   HEX: {pattern['data']}")
            print(f"   ASCII: {pattern['ascii']}")
            print()
        
        print("✅ Анализ завершен!")
        print("\n💡 Рекомендации:")
        print("1. Обратите внимание на данные рядом с 'CunBA'")
        print("2. Проверьте кандидатов ключей с помощью JWT-валидации")
        print("3. Используйте динамический анализ для подтверждения")

def main():
    if len(sys.argv) != 2:
        print("Использование: python unlock_analyzer.py <путь_к_unlock_файлу>")
        return
    
    analyzer = UnlockAnalyzer(sys.argv[1])
    analyzer.run_analysis()

if __name__ == "__main__":
    main()
