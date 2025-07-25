#!/usr/bin/env python3
"""
Продвинутый XOR деобфускатор для unlock бинарника
Поиск скрытых строк с различными методами XOR шифрования
"""

import re
import sys
import binascii
from pathlib import Path
from collections import defaultdict

class XORBreaker:
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
    
    def single_byte_xor_bruteforce(self):
        """Брутфорс одного байта XOR для всего файла"""
        print("🔓 Брутфорс одного байта XOR...")
        
        target_strings = [
            b'CunBA', b'HS256', b'SECRET_KEY', b'vehicle_id', 
            b'jwt', b'token', b'hmac', b'authorization',
            b'timestamp', b'issuer', b'iss'
        ]
        
        found_results = []
        
        for xor_key in range(1, 256):
            # XOR всего файла с этим ключом
            xored_data = bytes([b ^ xor_key for b in self.binary_data])
            
            # Ищем целевые строки в расшифрованных данных
            for target in target_strings:
                pos = 0
                while True:
                    pos = xored_data.find(target, pos)
                    if pos == -1:
                        break
                    
                    # Извлекаем контекст вокруг найденной строки
                    start = max(0, pos - 32)
                    end = min(len(xored_data), pos + len(target) + 32)
                    context = xored_data[start:end]
                    
                    # Проверяем, что контекст содержит читаемые символы
                    readable_count = sum(1 for b in context if 32 <= b <= 126)
                    if readable_count > len(context) * 0.5:  # Больше 50% читаемых символов
                        found_results.append({
                            'target': target.decode(),
                            'xor_key': xor_key,
                            'offset': pos,
                            'context': context.decode('ascii', errors='ignore'),
                            'hex_context': binascii.hexlify(context).decode()
                        })
                    
                    pos += 1
        
        return found_results
    
    def multi_byte_xor_patterns(self):
        """Поиск паттернов многобайтового XOR"""
        print("🔓 Поиск многобайтовых XOR паттернов...")
        
        found_patterns = []
        
        # Пробуем различные длины XOR ключей (2-8 байт)
        for key_length in range(2, 9):
            print(f"  Проверяем XOR ключи длиной {key_length} байт...")
            
            # Берем каждый key_length-й байт и анализируем частоты
            for start_offset in range(key_length):
                byte_positions = []
                for i in range(start_offset, len(self.binary_data), key_length):
                    if i < len(self.binary_data):
                        byte_positions.append(self.binary_data[i])
                
                if len(byte_positions) < 100:  # Слишком мало данных
                    continue
                
                # Анализируем частоты байтов
                byte_freqs = defaultdict(int)
                for b in byte_positions:
                    byte_freqs[b] += 1
                
                # Наиболее частый байт может быть результатом XOR с пробелом (0x20)
                most_frequent = max(byte_freqs.items(), key=lambda x: x[1])
                potential_xor_key = most_frequent[0] ^ 0x20  # Предполагаем XOR с пробелом
                
                # Проверяем, дает ли этот ключ осмысленные результаты
                test_data = bytes([byte_positions[i] ^ potential_xor_key for i in range(min(100, len(byte_positions)))])
                readable_count = sum(1 for b in test_data if 32 <= b <= 126)
                
                if readable_count > len(test_data) * 0.7:  # 70% читаемых символов
                    found_patterns.append({
                        'key_length': key_length,
                        'position': start_offset,
                        'xor_byte': potential_xor_key,
                        'confidence': readable_count / len(test_data),
                        'sample': test_data.decode('ascii', errors='ignore')[:50]
                    })
        
        return found_patterns
    
    def rolling_xor_analysis(self):
        """Анализ скользящего XOR (каждый байт XORится с предыдущим или с позицией)"""
        print("🔓 Анализ скользящего XOR...")
        
        results = []
        chunk_size = 64
        
        for i in range(0, len(self.binary_data) - chunk_size, chunk_size//4):
            chunk = self.binary_data[i:i+chunk_size]
            
            # Метод 1: XOR с предыдущим байтом
            decoded1 = bytearray()
            prev = 0
            for b in chunk:
                decoded1.append(b ^ prev)
                prev = b
            
            # Проверяем на наличие целевых строк
            decoded1_str = bytes(decoded1).decode('ascii', errors='ignore')
            if any(target in decoded1_str.lower() for target in ['cunba', 'hs256', 'secret', 'jwt']):
                results.append({
                    'method': 'XOR_with_previous',
                    'offset': hex(i),
                    'decoded': decoded1_str[:50],
                    'hex': binascii.hexlify(bytes(decoded1[:32])).decode()
                })
            
            # Метод 2: XOR с позицией
            decoded2 = bytearray()
            for j, b in enumerate(chunk):
                decoded2.append(b ^ (j & 0xFF))
            
            decoded2_str = bytes(decoded2).decode('ascii', errors='ignore')
            if any(target in decoded2_str.lower() for target in ['cunba', 'hs256', 'secret', 'jwt']):
                results.append({
                    'method': 'XOR_with_position',
                    'offset': hex(i),
                    'decoded': decoded2_str[:50],
                    'hex': binascii.hexlify(bytes(decoded2[:32])).decode()
                })
        
        return results
    
    def xor_with_known_plaintexts(self):
        """XOR анализ с известными открытыми текстами"""
        print("🔓 XOR анализ с известными открытыми текстами...")
        
        # Известные строки, которые могут быть в бинарнике
        known_plaintexts = [
            b'{"vehicle_id"',
            b'"iss":"CunBA"',
            b'"alg":"HS256"',
            b'HTTP/1.1',
            b'application/json',
            b'Authorization: Bearer',
            b'Content-Type:',
            b'webadb.miaosoft.cn'
        ]
        
        found_keys = []
        
        for plaintext in known_plaintexts:
            for i in range(len(self.binary_data) - len(plaintext)):
                cipher_chunk = self.binary_data[i:i+len(plaintext)]
                
                # Вычисляем потенциальный XOR ключ
                xor_key = bytes([c ^ p for c, p in zip(cipher_chunk, plaintext)])
                
                # Проверяем, является ли ключ повторяющимся паттерном
                key_patterns = []
                for key_len in [1, 2, 4, 8, 16]:
                    if len(xor_key) >= key_len:
                        pattern = xor_key[:key_len]
                        if all(xor_key[j] == pattern[j % key_len] for j in range(len(xor_key))):
                            key_patterns.append({
                                'pattern': pattern,
                                'length': key_len
                            })
                
                if key_patterns:
                    # Тестируем найденный ключ на большем участке
                    test_start = max(0, i - 64)
                    test_end = min(len(self.binary_data), i + len(plaintext) + 64)
                    test_chunk = self.binary_data[test_start:test_end]
                    
                    for pattern_info in key_patterns:
                        pattern = pattern_info['pattern']
                        decoded_test = bytes([b ^ pattern[j % len(pattern)] for j, b in enumerate(test_chunk)])
                        
                        # Проверяем качество расшифровки
                        readable_count = sum(1 for b in decoded_test if 32 <= b <= 126 or b in [9, 10, 13])
                        if readable_count > len(decoded_test) * 0.6:
                            found_keys.append({
                                'plaintext': plaintext.decode('ascii', errors='ignore'),
                                'offset': hex(i),
                                'xor_key': binascii.hexlify(pattern).decode(),
                                'key_length': len(pattern),
                                'quality': readable_count / len(decoded_test),
                                'decoded_sample': decoded_test.decode('ascii', errors='ignore')[:100]
                            })
        
        return found_keys
    
    def run_xor_analysis(self):
        """Запуск полного XOR анализа"""
        print("🔓 Запуск полного XOR анализа unlock бинарника...")
        print("=" * 60)
        
        if not self.load_binary():
            return
        
        # 1. Брутфорс одного байта
        print("\n🔑 1. Одиночный байт XOR брутфорс:")
        single_results = self.single_byte_xor_bruteforce()
        if single_results:
            for result in single_results[:10]:  # Показываем первые 10
                print(f"   🎯 Найдено '{result['target']}' с XOR ключом 0x{result['xor_key']:02x}")
                print(f"      Смещение: {result['offset']}")
                print(f"      Контекст: {result['context'][:60]}...")
                print()
        else:
            print("   Ничего не найдено")
        
        # 2. Многобайтовый XOR
        print("\n🔑 2. Многобайтовый XOR анализ:")
        multi_results = self.multi_byte_xor_patterns()
        if multi_results:
            for result in multi_results[:5]:
                print(f"   🎯 Паттерн длиной {result['key_length']}, позиция {result['position']}")
                print(f"      XOR байт: 0x{result['xor_byte']:02x}")
                print(f"      Уверенность: {result['confidence']:.2%}")
                print(f"      Образец: {result['sample']}")
                print()
        else:
            print("   Ничего не найдено")
        
        # 3. Скользящий XOR
        print("\n🔑 3. Скользящий XOR анализ:")
        rolling_results = self.rolling_xor_analysis()
        if rolling_results:
            for result in rolling_results[:5]:
                print(f"   🎯 Метод: {result['method']}")
                print(f"      Смещение: {result['offset']}")
                print(f"      Расшифровано: {result['decoded']}")
                print()
        else:
            print("   Ничего не найдено")
        
        # 4. XOR с известными открытыми текстами
        print("\n🔑 4. XOR анализ с известными текстами:")
        known_results = self.xor_with_known_plaintexts()
        if known_results:
            # Сортируем по качеству расшифровки
            known_results.sort(key=lambda x: x['quality'], reverse=True)
            
            for result in known_results[:5]:
                print(f"   🎯 Открытый текст: '{result['plaintext']}'")
                print(f"      XOR ключ: {result['xor_key']} (длина: {result['key_length']})")
                print(f"      Смещение: {result['offset']}")
                print(f"      Качество: {result['quality']:.2%}")
                print(f"      Расшифровано: {result['decoded_sample'][:80]}...")
                print()
        else:
            print("   Ничего не найдено")
        
        print("✅ XOR анализ завершен!")
        
        # Выводим лучшие кандидаты
        all_results = []
        all_results.extend(single_results)
        all_results.extend(known_results)
        
        if all_results:
            print(f"\n💎 Найдено {len(all_results)} потенциальных XOR ключей!")
            print("📝 Рекомендация: протестируйте найденные ключи с JWT валидатором")

def main():
    if len(sys.argv) != 2:
        print("Использование: python xor_breaker.py <путь_к_unlock_файлу>")
        return
    
    breaker = XORBreaker(sys.argv[1])
    breaker.run_xor_analysis()

if __name__ == "__main__":
    main()
