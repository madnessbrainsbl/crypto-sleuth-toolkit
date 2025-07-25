#!/usr/bin/env python3
"""
Целенаправленный извлекатель SECRET_KEY
Использует найденные XOR паттерны для поиска ключа
"""

import re
import sys
import binascii
import hashlib
from pathlib import Path

class SecretKeyExtractor:
    def __init__(self, binary_path):
        self.binary_path = Path(binary_path)
        self.binary_data = None
        self.potential_keys = []
        
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
    
    def extract_around_jwt_patterns(self):
        """Извлекаем данные вокруг найденных JWT паттернов"""
        print("🔍 Извлечение данных вокруг JWT паттернов...")
        
        # Найденные XOR ключи для JWT
        jwt_xor_keys = [0x04, 0x63, 0x72]
        
        for xor_key in jwt_xor_keys:
            print(f"\n🔑 Анализируем XOR ключ 0x{xor_key:02x}:")
            
            # XOR всего файла
            xored_data = bytes([b ^ xor_key for b in self.binary_data])
            
            # Ищем 'jwt' в расшифрованных данных
            pos = 0
            while True:
                pos = xored_data.find(b'jwt', pos)
                if pos == -1:
                    break
                
                # Извлекаем больший контекст (512 байт до и после)
                start = max(0, pos - 512)
                end = min(len(xored_data), pos + 512)
                context = xored_data[start:end]
                
                # Ищем потенциальные ключи в этом контексте
                self.find_keys_in_context(context, f"jwt_xor_{xor_key:02x}", pos)
                
                pos += 1
    
    def extract_around_iss_patterns(self):
        """Извлекаем данные вокруг найденных 'iss' паттернов (CunBA)"""
        print("🔍 Извлечение данных вокруг 'iss' паттернов...")
        
        # Найденные XOR ключи для iss
        iss_xor_keys = [0x31, 0x73]
        
        for xor_key in iss_xor_keys:
            print(f"\n🔑 Анализируем XOR ключ 0x{xor_key:02x}:")
            
            # XOR всего файла
            xored_data = bytes([b ^ xor_key for b in self.binary_data])
            
            # Ищем 'iss' и 'CunBA' в расшифрованных данных
            for target in [b'iss', b'CunBA']:
                pos = 0
                while True:
                    pos = xored_data.find(target, pos)
                    if pos == -1:
                        break
                    
                    # Извлекаем контекст
                    start = max(0, pos - 512)
                    end = min(len(xored_data), pos + 512)
                    context = xored_data[start:end]
                    
                    self.find_keys_in_context(context, f"{target.decode()}_xor_{xor_key:02x}", pos)
                    
                    pos += 1
    
    def find_keys_in_context(self, context, source, offset):
        """Поиск потенциальных ключей в контексте"""
        context_str = context.decode('ascii', errors='ignore')
        
        # Паттерны для поиска ключей
        key_patterns = [
            # Строки, которые могут содержать SECRET_KEY
            r'SECRET_KEY["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=]{16,})["\']?',
            r'secret["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=]{16,})["\']?',
            r'key["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=]{16,})["\']?',
            
            # JWT подписи и ключи (обычно base64)
            r'([A-Za-z0-9+/]{32,}={0,2})',
            
            # Hex строки (потенциальные ключи)
            r'([a-fA-F0-9]{32,64})',
            
            # Любые длинные строки рядом с JWT терминами
            r'(?:jwt|hmac|sign|key|secret).*?([A-Za-z0-9+/=]{20,})',
        ]
        
        for pattern in key_patterns:
            matches = re.finditer(pattern, context_str, re.IGNORECASE)
            for match in matches:
                potential_key = match.group(1) if match.groups() else match.group(0)
                
                if len(potential_key) >= 16:  # Минимальная длина ключа
                    self.potential_keys.append({
                        'key': potential_key,
                        'source': source,
                        'offset': offset,
                        'pattern': pattern,
                        'context': context_str[max(0, match.start()-50):match.end()+50]
                    })
    
    def search_hardcoded_strings(self):
        """Поиск захардкоженных строк без XOR"""
        print("🔍 Поиск захардкоженных строк...")
        
        # Ищем возможные ключи в открытом виде
        raw_str = self.binary_data.decode('ascii', errors='ignore')
        
        key_patterns = [
            r'SECRET_KEY["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=]{16,64})["\']?',
            r'(?:HMAC|JWT).*?KEY["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=]{16,64})["\']?',
            r'([a-fA-F0-9]{64})',  # 256-bit hex keys
            r'([A-Za-z0-9+/]{43}=)',  # 32-byte base64 keys
        ]
        
        for pattern in key_patterns:
            matches = re.finditer(pattern, raw_str, re.IGNORECASE)
            for match in matches:
                potential_key = match.group(1) if match.groups() else match.group(0)
                
                self.potential_keys.append({
                    'key': potential_key,
                    'source': 'hardcoded',
                    'offset': match.start(),
                    'pattern': pattern,
                    'context': raw_str[max(0, match.start()-50):match.end()+50]
                })
    
    def search_near_cunba_issuer(self):
        """Специальный поиск рядом с 'CunBA' (issuer)"""
        print("🔍 Специальный поиск рядом с issuer 'CunBA'...")
        
        # Ищем 'CunBA' с различными XOR ключами
        for xor_key in range(256):
            xored_cunba = bytes([ord(c) ^ xor_key for c in 'CunBA'])
            
            pos = 0
            while True:
                pos = self.binary_data.find(xored_cunba, pos)
                if pos == -1:
                    break
                
                # Расшифровываем область вокруг найденной строки
                start = max(0, pos - 256)
                end = min(len(self.binary_data), pos + 256)
                context_encrypted = self.binary_data[start:end]
                context_decrypted = bytes([b ^ xor_key for b in context_encrypted])
                
                # Проверяем, есть ли 'CunBA' в расшифрованном контексте
                if b'CunBA' in context_decrypted:
                    print(f"\n🎯 Найдено 'CunBA' с XOR ключом 0x{xor_key:02x} в смещении 0x{pos:x}")
                    
                    # Ищем ключи в этом контексте
                    self.find_keys_in_context(context_decrypted, f"cunba_area_xor_{xor_key:02x}", pos)
                    
                    # Выводим расшифрованный контекст
                    readable = context_decrypted.decode('ascii', errors='ignore')
                    print(f"   Контекст: {readable[:100]}...")
                
                pos += 1
    
    def generate_key_candidates(self):
        """Генерируем финальные кандидаты ключей"""
        print("\n🔑 Генерация финальных кандидатов SECRET_KEY...")
        
        unique_keys = {}
        
        for key_info in self.potential_keys:
            key = key_info['key']
            
            # Пропускаем слишком короткие или слишком длинные ключи
            if len(key) < 16 or len(key) > 128:
                continue
            
            # Пропускаем ключи с низкой энтропией
            if len(set(key)) < 6:
                continue
            
            if key not in unique_keys:
                unique_keys[key] = []
            unique_keys[key].append(key_info)
        
        # Сортируем по частоте встречаемости
        sorted_keys = sorted(unique_keys.items(), key=lambda x: len(x[1]), reverse=True)
        
        print(f"\n💎 Найдено {len(sorted_keys)} уникальных кандидатов ключей:")
        
        for i, (key, sources) in enumerate(sorted_keys[:10]):  # Показываем топ-10
            print(f"\n{i+1}. Ключ: {key}")
            print(f"   Длина: {len(key)} символов")
            print(f"   Найден в {len(sources)} местах")
            print(f"   Источники: {', '.join(set(s['source'] for s in sources))}")
            
            # Если ключ выглядит как hex, показываем его в разных форматах
            if re.match(r'^[a-fA-F0-9]+$', key):
                try:
                    hex_bytes = binascii.unhexlify(key)
                    print(f"   Как байты: {hex_bytes}")
                    print(f"   Как ASCII: {hex_bytes.decode('ascii', errors='ignore')}")
                except:
                    pass
            
            # Если ключ выглядит как base64, декодируем
            if re.match(r'^[A-Za-z0-9+/]+=*$', key):
                try:
                    import base64
                    decoded = base64.b64decode(key)
                    print(f"   Base64 декодирован: {binascii.hexlify(decoded).decode()}")
                except:
                    pass
        
        return sorted_keys
    
    def run_extraction(self):
        """Запуск полного извлечения"""
        print("🔑 Начинаем извлечение SECRET_KEY из unlock бинарника...")
        print("=" * 60)
        
        if not self.load_binary():
            return
        
        # 1. Поиск вокруг JWT паттернов
        self.extract_around_jwt_patterns()
        
        # 2. Поиск вокруг iss паттернов  
        self.extract_around_iss_patterns()
        
        # 3. Поиск захардкоженных строк
        self.search_hardcoded_strings()
        
        # 4. Специальный поиск рядом с CunBA
        self.search_near_cunba_issuer()
        
        # 5. Генерация финальных кандидатов
        candidates = self.generate_key_candidates()
        
        print("\n✅ Извлечение завершено!")
        print(f"\n💡 Найдено {len(candidates)} кандидатов для SECRET_KEY")
        print("📝 Рекомендация: протестируйте каждый кандидат с JWT валидатором")
        
        if candidates:
            print(f"\n🚀 Команды для тестирования топ-3 кандидатов:")
            for i, (key, _) in enumerate(candidates[:3]):
                print(f"python jwt_validator.py \"{key}\"")

def main():
    if len(sys.argv) != 2:
        print("Использование: python secret_key_extractor.py <путь_к_unlock_файлу>")
        return
    
    extractor = SecretKeyExtractor(sys.argv[1])
    extractor.run_extraction()

if __name__ == "__main__":
    main()
