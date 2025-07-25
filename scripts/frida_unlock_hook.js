/*
 * Frida скрипт для динамического анализа unlock бинарника
 * Перехватывает функции HMAC, JWT и связанные операции
 */

console.log("🚀 Frida скрипт для анализа unlock бинарника");
console.log("=" * 50);

// Глобальные переменные для хранения данных
var potentialKeys = [];
var jwtOperations = [];

// Функция для вывода hex данных
function hexdump(data, maxLength) {
    maxLength = maxLength || 64;
    var length = Math.min(data.byteLength, maxLength);
    var result = '';
    
    for (var i = 0; i < length; i += 16) {
        var hex = '';
        var ascii = '';
        
        for (var j = 0; j < 16 && (i + j) < length; j++) {
            var byte = data[i + j];
            hex += ('0' + byte.toString(16)).slice(-2) + ' ';
            ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
        }
        
        result += hex.padEnd(48) + ' | ' + ascii + '\n';
    }
    
    return result;
}

// Перехват функций HMAC
function hookHMACFunctions() {
    console.log("🔍 Поиск HMAC функций...");
    
    // Пытаемся найти HMAC функции по символам
    var hmacSymbols = [
        "HMAC_Init", "HMAC_Update", "HMAC_Final", "HMAC_CTX_new",
        "EVP_PKEY_new_mac_key", "EVP_DigestSignInit", "EVP_DigestSign"
    ];
    
    hmacSymbols.forEach(function(symbol) {
        try {
            var addr = Module.findExportByName(null, symbol);
            if (addr) {
                console.log("✓ Найдена функция: " + symbol + " в " + addr);
                
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        console.log("🔑 HMAC операция: " + symbol);
                        
                        // Для HMAC_Init - перехватываем ключ
                        if (symbol === "HMAC_Init" && args.length > 2) {
                            var keyPtr = args[1];
                            var keyLen = args[2].toInt32();
                            
                            if (keyPtr && !keyPtr.isNull() && keyLen > 0 && keyLen < 256) {
                                try {
                                    var keyData = keyPtr.readByteArray(keyLen);
                                    console.log("📋 Перехвачен HMAC ключ (длина: " + keyLen + "):");
                                    console.log(hexdump(new Uint8Array(keyData)));
                                    
                                    potentialKeys.push({
                                        data: keyData,
                                        length: keyLen,
                                        source: "HMAC_Init"
                                    });
                                } catch (e) {
                                    console.log("⚠ Ошибка чтения HMAC ключа: " + e);
                                }
                            }
                        }
                    },
                    onLeave: function(retval) {
                        // console.log("HMAC функция завершена: " + symbol);
                    }
                });
            }
        } catch (e) {
            // Символ не найден, продолжаем
        }
    });
}

// Перехват строковых операций для поиска JWT токенов
function hookStringOperations() {
    console.log("🔍 Настройка перехвата строковых операций...");
    
    // Перехват strcmp для JWT строк
    var strcmp = Module.findExportByName(null, "strcmp");
    if (strcmp) {
        Interceptor.attach(strcmp, {
            onEnter: function(args) {
                try {
                    var str1 = args[0].readCString();
                    var str2 = args[1].readCString();
                    
                    // Ищем JWT-связанные строки
                    var jwtPatterns = ["CunBA", "HS256", "jwt", "vehicle_id", "timestamp"];
                    
                    jwtPatterns.forEach(function(pattern) {
                        if ((str1 && str1.includes(pattern)) || (str2 && str2.includes(pattern))) {
                            console.log("🎯 JWT строка найдена: '" + str1 + "' vs '" + str2 + "'");
                        }
                    });
                } catch (e) {
                    // Игнорируем ошибки чтения строк
                }
            }
        });
    }
    
    // Перехват memcmp для сравнения бинарных данных
    var memcmp = Module.findExportByName(null, "memcmp");
    if (memcmp) {
        Interceptor.attach(memcmp, {
            onEnter: function(args) {
                var size = args[2].toInt32();
                
                // Интересуемся сравнениями размером с JWT подпись (32 байта)
                if (size === 32) {
                    console.log("🔍 Сравнение 32-байт данных (возможно, HMAC подпись)");
                    
                    try {
                        var data1 = args[0].readByteArray(size);
                        var data2 = args[1].readByteArray(size);
                        
                        console.log("Данные 1:");
                        console.log(hexdump(new Uint8Array(data1), 32));
                        console.log("Данные 2:");
                        console.log(hexdump(new Uint8Array(data2), 32));
                    } catch (e) {
                        console.log("⚠ Ошибка чтения данных memcmp: " + e);
                    }
                }
            }
        });
    }
}

// Поиск и перехват функций по паттернам инструкций
function hookByInstructionPatterns() {
    console.log("🔍 Поиск функций по паттернам инструкций...");
    
    // Сканируем память процесса для поиска паттернов
    Process.enumerateModules().forEach(function(module) {
        if (module.name === "unlock" || module.path.includes("unlock")) {
            console.log("📂 Анализируем модуль: " + module.name + " (" + module.base + ")");
            
            try {
                // Ищем паттерны ARM64 инструкций для HMAC операций
                var ranges = module.enumerateRanges("r-x");
                ranges.forEach(function(range) {
                    try {
                        // Простой поиск строки "CunBA" в исполняемой области
                        var cunbaPattern = "43756e4241"; // "CunBA" в hex
                        Memory.scan(range.base, range.size, cunbaPattern, {
                            onMatch: function(address, size) {
                                console.log("🎯 Найдена строка 'CunBA' по адресу: " + address);
                                
                                // Читаем контекст вокруг найденной строки
                                var context = address.sub(64).readByteArray(128);
                                console.log("Контекст:");
                                console.log(hexdump(new Uint8Array(context)));
                            },
                            onError: function(reason) {
                                console.log("⚠ Ошибка сканирования: " + reason);
                            },
                            onComplete: function() {
                                // console.log("Сканирование региона завершено");
                            }
                        });
                    } catch (e) {
                        console.log("⚠ Ошибка сканирования региона: " + e);
                    }
                });
            } catch (e) {
                console.log("⚠ Ошибка анализа модуля: " + e);
            }
        }
    });
}

// Перехват системных вызовов
function hookSystemCalls() {
    console.log("🔍 Настройка перехвата системных вызовов...");
    
    // Перехват getprop для vehicle_id
    var getprop = Module.findExportByName(null, "__system_property_get");
    if (getprop) {
        Interceptor.attach(getprop, {
            onEnter: function(args) {
                try {
                    var propName = args[0].readCString();
                    if (propName && propName.includes("vehicle_id")) {
                        console.log("🚗 Запрос vehicle_id: " + propName);
                        this.propName = propName;
                    }
                } catch (e) {
                    // Игнорируем ошибки
                }
            },
            onLeave: function(retval) {
                if (this.propName) {
                    try {
                        var value = this.context.r1.readCString(); // ARM64
                        console.log("🚗 vehicle_id получен: " + value);
                    } catch (e) {
                        console.log("⚠ Ошибка чтения vehicle_id: " + e);
                    }
                }
            }
        });
    }
}

// Главная функция инициализации
function main() {
    console.log("🔧 Инициализация перехватчиков...");
    
    // Запускаем все перехватчики
    hookHMACFunctions();
    hookStringOperations();
    hookSystemCalls();
    hookByInstructionPatterns();
    
    console.log("✅ Все перехватчики настроены. Ожидаем активности...");
    console.log("💡 Теперь запустите unlock бинарник на устройстве");
    
    // Периодический вывод найденных ключей
    setInterval(function() {
        if (potentialKeys.length > 0) {
            console.log("📊 Статус: найдено " + potentialKeys.length + " потенциальных ключей");
            potentialKeys.forEach(function(key, index) {
                console.log("Ключ #" + (index + 1) + " (источник: " + key.source + ", длина: " + key.length + "):");
                console.log(hexdump(new Uint8Array(key.data), 32));
            });
        }
    }, 10000); // Каждые 10 секунд
}

// Запуск
main();
