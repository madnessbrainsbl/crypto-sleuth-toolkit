#!/usr/bin/env python3
"""
Генератор SECRET_KEY на основе системной информации QNX
Имитирует возможные источники данных для генерации ключа
"""
import jwt
import hashlib
import hmac
import itertools
from datetime import datetime

# Рабочий токен
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"
EXACT_PAYLOAD = {"vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce", "iss": "CunBA", "timestamp": 1753096202}

class QNXSystemKeyGenerator:
    def __init__(self):
        # Возможные системные данные (имитация QNX getprop)
        self.qnx_properties = {
            # Системная информация
            'ro.serialno': ['QNX123456789', 'SN987654321', 'SERIAL123456'],
            'ro.hardware': ['qualcomm', 'qcom', 'msm8155', '8155', 'sdm845'],
            'ro.product.model': ['mega', 'MEGA', 'automotive', 'platform'],
            'ro.product.name': ['cunba', 'CunBA', 'CUNBA', 'unlock'],
            'ro.build.id': ['A11', 'B22', 'C33', 'QNX123', 'BUILD456'],
            'ro.build.version': ['1.0', '2.0', '11.0', 'release'],
            'ro.build.fingerprint': ['qnx/mega/unlock', 'cunba/automotive/A11'],
            
            # Hardware специфичные
            'persist.vendor.radio.imei': ['123456789012345', '862061234567890'],
            'ro.boot.serialno': ['BOOT123', 'SER456', EXACT_PAYLOAD['vehicle_id'][:16]],
            'sys.boot.reason': ['reboot', 'unlock', 'normal', 'recovery'],
            
            # Автомобильные системы
            'vehicle.vin': ['WBAFR5C50EA123456', 'VIN1234567890'],
            'ecu.serial': ['ECU123456', 'ECUSERIAL789'],
            'platform.version': ['A11', 'automotive_11', 'mega_platform'],
        }
        
        # Известные данные из токена
        self.token_data = EXACT_PAYLOAD
        
        # Магические константы из Ghidra анализа
        self.ghidra_constants = [
            0x20000f, 0x20000, 0x3fff, 0x3ffff, 0x3ff, 0x800,
            0x5db4, 0x142c, 0x5430, 0x5d00, 0x5d20, 0x18, 0x5c90,
            0x103994, 0x10d54c, 0x10d5c4, 0x109ac4, 0x10d8e4
        ]
    
    def generate_base_candidates(self):
        """Генерирует базовые кандидаты из системной информации"""
        candidates = set()
        
        # 1. Прямое использование системных свойств
        for prop_name, values in self.qnx_properties.items():
            for value in values:
                candidates.add(value)
                candidates.add(value.upper())
                candidates.add(value.lower())
                # Хеши от свойств
                candidates.add(hashlib.md5(value.encode()).hexdigest())
                candidates.add(hashlib.sha256(value.encode()).hexdigest())
                candidates.add(hashlib.sha1(value.encode()).hexdigest())
        
        # 2. Данные из токена
        candidates.add(self.token_data['vehicle_id'])
        candidates.add(self.token_data['iss'])
        candidates.add(str(self.token_data['timestamp']))
        
        # 3. Константы из Ghidra
        for const in self.ghidra_constants:
            candidates.add(str(const))
            candidates.add(f"{const:x}")
            candidates.add(f"0x{const:x}")
        
        return candidates
    
    def generate_combined_candidates(self):
        """Генерирует комбинированные кандидаты"""
        candidates = set()
        
        # Базовые строки для комбинирования
        base_strings = [
            'CunBA', 'cunba', 'unlock', 'mega', 'platform', 'A11',
            self.token_data['vehicle_id'], self.token_data['iss'],
            str(self.token_data['timestamp'])
        ]
        
        # Системные данные
        system_strings = []
        for values in self.qnx_properties.values():
            system_strings.extend(values[:2])  # Берем по 2 значения от каждого свойства
        
        # Разделители
        separators = ['', '_', '-', '.', ':', '|', '+', '@']
        
        # Комбинации base + system
        for base in base_strings[:5]:  # Ограничиваем количество
            for system in system_strings[:10]:  # Ограничиваем количество
                for sep in separators[:4]:  # Ограничиваем количество
                    # base + separator + system
                    combo1 = f"{base}{sep}{system}"
                    candidates.add(combo1)
                    
                    # system + separator + base
                    combo2 = f"{system}{sep}{base}"
                    candidates.add(combo2)
                    
                    # Хеши комбинаций
                    candidates.add(hashlib.md5(combo1.encode()).hexdigest())
                    candidates.add(hashlib.md5(combo2.encode()).hexdigest())
        
        return candidates
    
    def generate_timestamp_based_keys(self):
        """Генерирует ключи на основе временных меток"""
        candidates = set()
        
        timestamp = self.token_data['timestamp']
        dt = datetime.fromtimestamp(timestamp)
        
        # Различные представления времени
        time_variants = [
            str(timestamp),
            str(timestamp)[:10],  # Первые 10 цифр
            str(timestamp)[-10:], # Последние 10 цифр
            hex(timestamp)[2:],   # Hex без 0x
            f"{timestamp:x}",     # Hex
            
            # Компоненты даты
            str(dt.year),
            str(dt.month),
            str(dt.day),
            str(dt.hour),
            str(dt.minute),
            
            # Комбинации
            f"{dt.year}{dt.month:02d}{dt.day:02d}",
            f"{dt.hour:02d}{dt.minute:02d}",
            f"{dt.year}{dt.month:02d}",
        ]
        
        # Комбинируем время с базовыми строками
        base_strings = ['CunBA', 'cunba', 'unlock', 'mega']
        
        for time_val in time_variants:
            candidates.add(time_val)
            
            for base in base_strings:
                candidates.add(f"{base}_{time_val}")
                candidates.add(f"{time_val}_{base}")
                candidates.add(f"{base}{time_val}")
                candidates.add(f"{time_val}{base}")
                
                # Хеши
                combo = f"{base}_{time_val}"
                candidates.add(hashlib.md5(combo.encode()).hexdigest())
                candidates.add(hashlib.sha256(combo.encode()).hexdigest())
        
        return candidates
    
    def generate_vehicle_id_based_keys(self):
        """Генерирует ключи на основе vehicle_id"""
        candidates = set()
        
        vehicle_id = self.token_data['vehicle_id']
        
        # Различные трансформации vehicle_id
        transformations = [
            vehicle_id,
            vehicle_id.upper(),
            vehicle_id[:16],  # Первые 16 символов
            vehicle_id[:8],   # Первые 8 символов
            vehicle_id[-16:], # Последние 16 символов
            vehicle_id[-8:],  # Последние 8 символов
            vehicle_id[8:24], # Средние 16 символов
        ]
        
        base_strings = ['CunBA', 'unlock', 'key', 'secret', 'hmac']
        
        for transform in transformations:
            candidates.add(transform)
            
            for base in base_strings:
                candidates.add(f"{base}_{transform}")
                candidates.add(f"{transform}_{base}")
                candidates.add(f"{base}{transform}")
                
                # Хеши
                combo = f"{base}_{transform}"
                candidates.add(hashlib.md5(combo.encode()).hexdigest())
        
        # XOR операции с vehicle_id
        try:
            vid_int = int(vehicle_id, 16)
            for const in self.ghidra_constants[:5]:  # Первые 5 констант
                xor_result = vid_int ^ const
                candidates.add(f"{xor_result:x}")
                candidates.add(str(xor_result))
        except:
            pass
        
        return candidates
    
    def generate_mathematical_keys(self):
        """Генерирует ключи на основе математических операций"""
        candidates = set()
        
        # Базовые числовые данные
        timestamp = self.token_data['timestamp']
        
        try:
            vehicle_id_int = int(self.token_data['vehicle_id'], 16)
        except:
            vehicle_id_int = hash(self.token_data['vehicle_id']) & 0xFFFFFFFF
        
        # Математические операции
        operations = [
            timestamp & 0xFFFFFFFF,
            timestamp ^ 0x12345678,
            timestamp + 0x1000,
            timestamp - 0x1000,
            timestamp * 7 % 0xFFFFFFFF,
            (timestamp >> 8) & 0xFFFFFF,
            
            # С vehicle_id
            vehicle_id_int & 0xFFFFFFFF,
            vehicle_id_int ^ timestamp,
            (vehicle_id_int + timestamp) & 0xFFFFFFFF,
            (vehicle_id_int - timestamp) & 0xFFFFFFFF,
        ]
        
        # Комбинации с константами Ghidra
        for op_result in operations:
            for const in self.ghidra_constants[:5]:
                math_result = (op_result ^ const) & 0xFFFFFFFF
                candidates.add(f"{math_result:x}")
                candidates.add(str(math_result))
        
        return candidates
    
    def test_all_generated_keys(self):
        """Тестирует все сгенерированные ключи"""
        print("🔧 ГЕНЕРАЦИЯ КЛЮЧЕЙ НА ОСНОВЕ СИСТЕМНОЙ ИНФОРМАЦИИ QNX")
        print("="*70)
        
        all_candidates = set()
        
        # Собираем кандидатов из всех источников
        print("📊 Генерация кандидатов...")
        all_candidates.update(self.generate_base_candidates())
        print(f"  Базовые кандидаты: +{len(all_candidates)}")
        
        combined = self.generate_combined_candidates()
        all_candidates.update(combined)
        print(f"  Комбинированные: +{len(combined)}")
        
        timestamp_based = self.generate_timestamp_based_keys()
        all_candidates.update(timestamp_based)
        print(f"  На основе времени: +{len(timestamp_based)}")
        
        vehicle_based = self.generate_vehicle_id_based_keys()
        all_candidates.update(vehicle_based)
        print(f"  На основе vehicle_id: +{len(vehicle_based)}")
        
        math_based = self.generate_mathematical_keys()
        all_candidates.update(math_based)
        print(f"  Математические: +{len(math_based)}")
        
        print(f"\n🎯 Общее количество уникальных кандидатов: {len(all_candidates)}")
        
        # Сохраняем всех кандидатов
        self.save_candidates_to_file(all_candidates, "qnx_system_candidates.txt")
        
        # Тестируем
        print(f"\n🧪 ТЕСТИРОВАНИЕ КАНДИДАТОВ:")
        print("-" * 50)
        
        tested = 0
        for candidate in all_candidates:
            if self.test_key(candidate):
                print(f"\n🎉 НАЙДЕН SECRET_KEY: '{candidate}'")
                self.generate_new_tokens(candidate)
                return candidate
            
            tested += 1
            if tested % 200 == 0:
                print(f"Протестировано: {tested}/{len(all_candidates)}")
        
        print(f"\n❌ SECRET_KEY не найден среди {len(all_candidates)} кандидатов")
        print(f"💾 Все кандидаты сохранены в qnx_system_candidates.txt")
        return None
    
    def save_candidates_to_file(self, candidates, filename):
        """Сохраняет кандидатов в файл"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"# QNX System-based SECRET_KEY candidates\n")
            f.write(f"# Total candidates: {len(candidates)}\n\n")
            
            for candidate in sorted(candidates, key=lambda x: (len(x), x)):
                f.write(f"{candidate}\n")
    
    def test_key(self, key):
        """Тестирует ключ"""
        try:
            test_token = jwt.encode(EXACT_PAYLOAD, key, algorithm='HS256')
            return test_token == WORKING_TOKEN
        except:
            return False
    
    def generate_new_tokens(self, secret_key):
        """Генерирует новые токены с найденным ключом"""
        print(f"\n✅ ТЕСТИРОВАНИЕ НАЙДЕННОГО КЛЮЧА: '{secret_key}'")
        
        # Токен с новым временем
        new_payload1 = EXACT_PAYLOAD.copy()
        new_payload1['timestamp'] = 1753099999
        new_token1 = jwt.encode(new_payload1, secret_key, algorithm='HS256')
        
        # Токен с другим временем
        new_payload2 = EXACT_PAYLOAD.copy()
        new_payload2['timestamp'] = int(datetime.now().timestamp())
        new_token2 = jwt.encode(new_payload2, secret_key, algorithm='HS256')
        
        print(f"🎯 Новый токен 1 (timestamp: {new_payload1['timestamp']}):")
        print(f"   {new_token1}")
        print(f"🎯 Новый токен 2 (timestamp: {new_payload2['timestamp']}):")
        print(f"   {new_token2}")

if __name__ == "__main__":
    generator = QNXSystemKeyGenerator()
    result = generator.test_all_generated_keys()
    
    if not result:
        print(f"\n💡 РЕКОМЕНДАЦИИ ДЛЯ ДАЛЬНЕЙШЕГО ПОИСКА:")
        print("1. Получите реальную системную информацию с QNX устройства:")
        print("   - getprop | grep -E '(serial|build|hardware|version)'")
        print("   - cat /proc/cpuinfo")
        print("   - cat /proc/version")
        print("2. Проверьте файлы конфигурации:")
        print("   - /etc/passwd, /etc/hostname, /etc/machine-id")
        print("3. Используйте GDB для runtime анализа")
        print("4. Декомпилируйте криптофункции в Ghidra")
