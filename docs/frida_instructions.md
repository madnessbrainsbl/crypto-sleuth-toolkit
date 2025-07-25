# Инструкции по динамическому анализу с Frida

## Использование созданного Frida скрипта

### 1. Установка Frida
```bash
pip install frida-tools
```

### 2. Подключение к Android устройству
```bash
# Через USB (ADB)
adb devices
frida-ps -U  # Список процессов

# Через сеть (если Frida server запущен на устройстве)
frida-ps -H [IP_ADDRESS]
```

### 3. Запуск анализа unlock процесса
```bash
# Если процесс уже запущен
frida -U -n unlock -l frida_crypto_hunter.js

# Если нужно запустить приложение
frida -U -f com.unlock.app -l frida_crypto_hunter.js --no-pause

# Через PID процесса
frida -U -p [PID] -l frida_crypto_hunter.js
```

### 4. Что искать в выводе Frida:
- **HMAC KEY FOUND**: Найденные HMAC ключи
- **JWT TOKEN FOUND**: Найденные JWT токены  
- **CunBA string**: Строки содержащие CunBA
- **Potential key string**: Потенциальные ключи
- **System time requested**: Запросы системного времени

## Альтернативные подходы

### 1. Анализ памяти процесса (без root)
```bash
# Дамп карт памяти процесса
adb shell "cat /proc/$(pidof unlock)/maps"

# Чтение памяти (требует root)
adb shell "dd if=/proc/$(pidof unlock)/mem bs=1 skip=START_ADDRESS count=SIZE"
```

### 2. Мониторинг системных вызовов
```bash
# strace на Android (требует root)
adb shell "strace -p $(pidof unlock) -e trace=openat,read,write -s 1000"

# ltrace (если доступен)
adb shell "ltrace -p $(pidof unlock)"
```

### 3. Анализ сетевого трафика
```bash
# tcpdump на устройстве
adb shell "tcpdump -i wlan0 -w /sdcard/unlock_traffic.pcap"

# Или через PC proxy
# Настроить proxy в Wi-Fi настройках Android
```

## Поиск ключа в других местах

### 1. Системные файлы
```bash
# Поиск конфигурационных файлов
adb shell "find /data/data -name '*unlock*' -o -name '*cunba*' -o -name '*mega*'"

# Поиск в shared preferences
adb shell "find /data/data -name '*.xml' | xargs grep -l 'CunBA\|unlock\|key\|secret'"

# Поиск в базах данных
adb shell "find /data/data -name '*.db' -o -name '*.sqlite'"
```

### 2. Переменные окружения
```bash
adb shell "cat /proc/$(pidof unlock)/environ"
```

### 3. Анализ библиотек
```bash
# Список загруженных библиотек
adb shell "cat /proc/$(pidof unlock)/maps | grep '\.so'"

# Анализ конкретной библиотеки
adb pull /system/lib64/libcrypto.so
strings libcrypto.so | grep -i hmac
```

## Дополнительные Frida скрипты

### Перехват конкретных функций
```javascript
// Если известны имена функций в бинарнике
var module = Process.getModuleByName("unlock");
var func_addr = module.getExportByName("generate_token");
Interceptor.attach(func_addr, {
    onEnter: function(args) {
        console.log("[+] generate_token called");
    },
    onLeave: function(retval) {
        console.log("[+] generate_token result: " + retval);
    }
});
```

### Перехват malloc/free для поиска ключей
```javascript
Interceptor.attach(Module.findExportByName("libc.so", "malloc"), {
    onLeave: function(retval) {
        // Отслеживаем выделение памяти
        this.ptr = retval;
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "memcpy"), {
    onEnter: function(args) {
        // Перехватываем копирование данных
        var data = Memory.readUtf8String(args[1], 32);
        if (data.includes("CunBA") || data.length >= 16) {
            console.log("[+] memcpy potential key: " + data);
        }
    }
});
```

## Результаты анализа

После запуска Frida скрипта:

1. **Сохраните весь вывод** в файл для анализа
2. **Обратите внимание на**:
   - Строки содержащие "CunBA"
   - HMAC ключи (любой длины)
   - JWT токены
   - Timestamp операции
3. **Протестируйте найденные ключи** с помощью `test_working_token.py`

## Если Frida не работает

### Альтернативы:
1. **Xposed Framework** (требует root)
2. **Manual reverse engineering** с Ghidra/IDA
3. **Анализ APK файла** если доступен
4. **Мониторинг логов** Android

```bash
# Логи Android
adb logcat | grep -i "cunba\|unlock\|jwt\|hmac\|key"

# Системные логи
adb shell dmesg | grep unlock
```

## Следующие шаги

Если динамический анализ не даст результатов:
1. Проанализировать другие связанные файлы/процессы
2. Исследовать сетевые запросы приложения  
3. Попробовать обратную инженерию с другими инструментами
4. Рассмотреть возможность что ключ генерируется алгоритмически на основе системных данных
