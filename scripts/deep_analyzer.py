#!/usr/bin/env python3
"""
Углубленный анализатор unlock бинарника
Поиск обфусцированных и зашифрованных данных
"""

import re
import sys
import binascii
import struct
from pathlib import Path
from collections import Counter

class DeepUnlockAnalyzer:
    def __init__(self, binary_path):
        self.binary_path = Path(binary_path)
        self.binary_data = None
        
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
    
    def search_xor_patterns(self):
        """Поиск XOR-обфусцированных строк"""
        print("🔍 Поиск XOR-обфусцированных строк...")
        
        target_strings = [b'CunBA', b'HS256', b'SECRET_KEY', b'vehicle_id']
        found_patterns = []
        
        for target in target_strings:
            for xor_key in range(1, 256):
                xored_target = bytes([b ^ xor_key for b in target])
                
                pos = 0
                while True:
                    pos = self.binary_data.find(xored_target, pos)
                    if pos == -1:
                        break
                    
                    found_patterns.append({
                        'original': target.decode(),
                        'xor_key': xor_key,
                        'offset': hex(pos),
                        'xored_bytes': binascii.hexlify(xored_target).decode()
                    })
                    pos += 1
        
        return found_patterns
    
    def search_base64_patterns(self):
        """Поиск Base64 закодированных данных"""
        print("🔍 Поиск Base64 закодированных данных...")
        
        # Ищем длинные Base64 последовательности
        base64_pattern = rb'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.finditer(base64_pattern, self.binary_data)
        
        base64_candidates = []
        for match in matches:
            try:
                encoded = match.group(0).decode('ascii')
                # Добавляем паддинг если нужно
                while len(encoded) % 4 != 0:
                    encoded += '='
                
                import base64
                decoded = base64.b64decode(encoded)
                
                # Проверяем, содержит ли декодированное что-то интересное
                if any(keyword in decoded for keyword in [b'CunBA', b'HS256', b'jwt']):
                    base64_candidates.append({
                        'offset': hex(match.start()),
                        'encoded': encoded[:50] + ('...' if len(encoded) > 50 else ''),
                        'decoded': decoded[:100] + (b'...' if len(decoded) > 100 else b''),
                        'decoded_ascii': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in decoded[:100])
                    })
            except:
                continue
        
        return base64_candidates
    
    def search_entropy_regions(self):
        """Поиск регионов с высокой энтропией (возможно зашифрованные ключи)"""
        print("🔍 Анализ энтропии для поиска зашифрованных данных...")
        
        chunk_size = 32
        high_entropy_regions = []
        
        for i in range(0, len(self.binary_data) - chunk_size, 4):
            chunk = self.binary_data[i:i+chunk_size]
            
            # Вычисляем энтропию
            byte_counts = Counter(chunk)
            entropy = 0
            import math
            for count in byte_counts.values():
                p = count / len(chunk)
                if p > 0:
                    entropy -= p * math.log2(p)
            
            # Если энтропия высокая и данные не являются очевидно исполняемым кодом
            if entropy > 6.5:  # Высокая энтропия
                # Проверяем, что это не исполняемый код ARM64
                if not self.looks_like_arm64_code(chunk):
                    high_entropy_regions.append({
                        'offset': hex(i),
                        'entropy': round(entropy, 2),
                        'data': binascii.hexlify(chunk).decode(),
                        'ascii': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                    })
        
        # Возвращаем топ-10 регионов с наивысшей энтропией
        return sorted(high_entropy_regions, key=lambda x: x['entropy'], reverse=True)[:10]
    
    def looks_like_arm64_code(self, data):
        """Простая эвристика для определения ARM64 кода"""
        if len(data) < 8:
            return False
            
        # Проверяем на типичные ARM64 инструкции
        common_arm64_patterns = [
            b'\\x1f\\x20\\x03\\xd5',  # nop
            b'\\xfd\\x7b',            # stp fp, lr
            b'\\xfd\\x03',            # mov fp, sp
            b'\\xe0\\x03'             # mov x0, x
        ]
        
        for pattern in common_arm64_patterns:
            if pattern in data:
                return True
        return False
    
    def search_nearby_data_sections(self):
        """Поиск в секциях данных рядом с кодом"""
        print("🔍 Анализ секций данных...")
        
        if len(self.binary_data) < 64:
            return []
        
        # Простой парсинг ELF для поиска секций
        try:
            # Читаем section header offset
            shoff = struct.unpack('<Q', self.binary_data[40:48])[0]
            shentsize = struct.unpack('<H', self.binary_data[58:60])[0]
            shnum = struct.unpack('<H', self.binary_data[60:62])[0]
            
            sections = []
            for i in range(shnum):
                if shoff + i * shentsize + shentsize > len(self.binary_data):
                    break
                    
                sh_offset = shoff + i * shentsize
                sh_type = struct.unpack('<I', self.binary_data[sh_offset + 4:sh_offset + 8])[0]
                sh_addr = struct.unpack('<Q', self.binary_data[sh_offset + 16:sh_offset + 24])[0]
                sh_offset_data = struct.unpack('<Q', self.binary_data[sh_offset + 24:sh_offset + 32])[0]
                sh_size = struct.unpack('<Q', self.binary_data[sh_offset + 32:sh_offset + 40])[0]
                
                # Ищем секции данных (.data, .rodata, .bss)
                if sh_type in [1, 2, 8]:  # PROGBITS, SYMTAB, NOBITS
                    sections.append({
                        'index': i,
                        'type': sh_type,
                        'addr': hex(sh_addr),
                        'offset': sh_offset_data,
                        'size': sh_size
                    })
            
            return sections
        except:
            return []
    
    def search_string_table(self):
        """Поиск в таблицах строк"""
        print("🔍 Анализ таблиц строк...")
        
        # Ищем null-terminated строки длиной от 4 до 64 символов
        string_pattern = rb'[\x20-\x7e]{4,64}\x00'
        matches = re.finditer(string_pattern, self.binary_data)
        
        interesting_strings = []
        keywords = ['secret', 'key', 'jwt', 'token', 'hmac', 'cunba', 'vehicle']
        
        for match in matches:
            string = match.group(0)[:-1].decode('ascii', errors='ignore').lower()
            if any(keyword in string for keyword in keywords):
                interesting_strings.append({
                    'offset': hex(match.start()),
                    'string': match.group(0)[:-1].decode('ascii', errors='ignore'),
                    'length': len(match.group(0)) - 1
                })
        
        return interesting_strings
    
    def run_deep_analysis(self):
        """Запуск углубленного анализа"""
        print("🔍 Начинаем углубленный анализ unlock бинарника...")
        print("=" * 60)
        
        if not self.load_binary():
            return
        
        # 1. Поиск XOR-обфусцированных строк
        print("\n🔐 1. Поиск XOR-обфусцированных строк:")
        xor_patterns = self.search_xor_patterns()
        if xor_patterns:
            for pattern in xor_patterns[:10]:  # Показываем первые 10
                print(f"   • '{pattern['original']}' с XOR ключом {pattern['xor_key']} (0x{pattern['xor_key']:02x}) в {pattern['offset']}")
        else:
            print("   Не найдено")
        
        # 2. Поиск Base64 данных
        print("\n🔤 2. Поиск Base64 закодированных данных:")
        b64_patterns = self.search_base64_patterns()
        if b64_patterns:
            for pattern in b64_patterns[:5]:
                print(f"   Смещение: {pattern['offset']}")
                print(f"   Encoded: {pattern['encoded']}")
                print(f"   Decoded: {pattern['decoded_ascii']}")
                print()
        else:
            print("   Не найдено")
        
        # 3. Анализ энтропии
        print("\n📊 3. Регионы с высокой энтропией (потенциальные ключи):")
        entropy_regions = self.search_entropy_regions()
        for region in entropy_regions[:5]:
            print(f"   Смещение: {region['offset']}, энтропия: {region['entropy']}")
            print(f"   HEX: {region['data'][:64]}...")
            print(f"   ASCII: {region['ascii'][:32]}...")
            print()
        
        # 4. Анализ секций
        print("\n📋 4. Анализ ELF секций:")
        sections = self.search_nearby_data_sections()
        for section in sections[:5]:
            print(f"   Секция #{section['index']}: тип {section['type']}, адрес {section['addr']}, размер {section['size']}")
        
        # 5. Поиск интересных строк
        print("\n🔤 5. Интересные строки:")
        strings = self.search_string_table()
        for string in strings[:10]:
            print(f"   {string['offset']}: '{string['string']}'")
        
        print("\n✅ Углубленный анализ завершен!")
        print("\n💡 Следующие шаги:")
        print("1. Проверьте регионы с высокой энтропией - возможно, там зашифрованные ключи")
        print("2. Попробуйте XOR-деобфускацию найденных паттернов")
        print("3. Используйте динамический анализ с Frida")

def main():
    if len(sys.argv) != 2:
        print("Использование: python deep_analyzer.py <путь_к_unlock_файлу>")
        return
    
    analyzer = DeepUnlockAnalyzer(sys.argv[1])
    analyzer.run_deep_analysis()

if __name__ == "__main__":
    main()
