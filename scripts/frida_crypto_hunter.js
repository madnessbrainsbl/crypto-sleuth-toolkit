/*
 * Frida скрипт для перехвата криптографических функций и поиска JWT ключей
 * Использование: frida -U -f com.target.app -l frida_crypto_hunter.js --no-pause
 */

console.log("[*] Frida Crypto Hunter - поиск JWT/HMAC ключей");

// Глобальные переменные для сохранения данных
var foundKeys = [];
var hmacOperations = [];

Java.perform(function() {
    console.log("[+] Java runtime доступен, начинаем перехват...");

    // ========== ПЕРЕХВАТ HMAC ОПЕРАЦИЙ ==========
    try {
        var Mac = Java.use("javax.crypto.Mac");
        console.log("[+] Найден javax.crypto.Mac");

        // Перехват инициализации с ключом
        Mac.init.overload('java.security.Key').implementation = function(key) {
            try {
                var keyBytes = key.getEncoded();
                var keyString = "";
                
                if (keyBytes) {
                    // Конвертируем в строку
                    try {
                        keyString = Java.use("java.lang.String").$new(keyBytes, "UTF-8");
                        console.log("[+] HMAC KEY FOUND: '" + keyString + "'");
                        console.log("[+] Key bytes: " + bytesToHex(keyBytes));
                        foundKeys.push({type: "HMAC", key: keyString, bytes: bytesToHex(keyBytes)});
                    } catch(e) {
                        console.log("[+] Key bytes (hex): " + bytesToHex(keyBytes));
                        foundKeys.push({type: "HMAC", key: null, bytes: bytesToHex(keyBytes)});
                    }
                }
            } catch(e) {
                console.log("[!] Error in Mac.init: " + e);
            }
            return this.init(key);
        };

        // Перехват финальной операции
        Mac.doFinal.overload('[B').implementation = function(data) {
            try {
                var algorithm = this.getAlgorithm();
                console.log("[+] HMAC doFinal - Algorithm: " + algorithm);
                console.log("[+] Input data: " + bytesToHex(data));
                
                var result = this.doFinal(data);
                console.log("[+] HMAC Result: " + bytesToHex(result));
                
                // Попытаемся получить строковое представление данных
                try {
                    var inputString = Java.use("java.lang.String").$new(data, "UTF-8");
                    console.log("[+] Input as string: " + inputString);
                } catch(e) {}
                
                hmacOperations.push({
                    algorithm: algorithm,
                    input: bytesToHex(data),
                    output: bytesToHex(result)
                });
                
                return result;
            } catch(e) {
                console.log("[!] Error in Mac.doFinal: " + e);
                return this.doFinal(data);
            }
        };

    } catch(e) {
        console.log("[!] Mac class not found: " + e);
    }

    // ========== ПЕРЕХВАТ JWT БИБЛИОТЕК ==========
    
    // Java JWT библиотека
    try {
        var JwtBuilder = Java.use("io.jsonwebtoken.JwtBuilder");
        console.log("[+] Найден io.jsonwebtoken.JwtBuilder");
        
        JwtBuilder.signWith.overload('java.security.Key').implementation = function(key) {
            try {
                var keyBytes = key.getEncoded();
                var keyString = Java.use("java.lang.String").$new(keyBytes, "UTF-8");
                console.log("[+] JWT SIGN KEY: '" + keyString + "'");
                foundKeys.push({type: "JWT", key: keyString, bytes: bytesToHex(keyBytes)});
            } catch(e) {
                console.log("[!] Error in JwtBuilder.signWith: " + e);
            }
            return this.signWith(key);
        };
    } catch(e) {
        console.log("[-] io.jsonwebtoken.JwtBuilder not found");
    }

    // Auth0 JWT библиотека
    try {
        var Algorithm = Java.use("com.auth0.jwt.algorithms.Algorithm");
        console.log("[+] Найден com.auth0.jwt.algorithms.Algorithm");
    } catch(e) {
        console.log("[-] com.auth0.jwt.algorithms.Algorithm not found");
    }

    // ========== ПЕРЕХВАТ СТРОКОВЫХ ОПЕРАЦИЙ ==========
    
    // Поиск Base64 операций
    try {
        var Base64 = Java.use("android.util.Base64");
        Base64.encodeToString.overload('[B', 'int').implementation = function(data, flags) {
            var result = this.encodeToString(data, flags);
            if (result.length > 50) { // Длинные base64 строки могут быть токенами
                console.log("[+] Base64 encode (long): " + result.substring(0, 50) + "...");
            }
            return result;
        };
        
        Base64.decode.overload('java.lang.String', 'int').implementation = function(str, flags) {
            if (str.length > 50) {
                console.log("[+] Base64 decode (long): " + str.substring(0, 50) + "...");
            }
            return this.decode(str, flags);
        };
    } catch(e) {
        console.log("[-] Base64 class not found");
    }

    // ========== ПОИСК JWT ТОКЕНОВ В СТРОКАХ ==========
    
    var String = Java.use("java.lang.String");
    String.getBytes.overload().implementation = function() {
        var str = this.toString();
        
        // JWT паттерн (header.payload.signature)
        if (str.match(/^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/)) {
            console.log("[+] JWT TOKEN FOUND: " + str);
            foundKeys.push({type: "JWT_TOKEN", token: str});
        }
        
        // Поиск CunBA в строках
        if (str.includes("CunBA") || str.includes("cunba")) {
            console.log("[+] CunBA string: " + str);
        }
        
        // Поиск длинных строк (возможные ключи)
        if (str.length >= 16 && str.length <= 128 && str.match(/^[A-Za-z0-9+/=_-]+$/)) {
            console.log("[+] Potential key string: " + str);
        }
        
        return this.getBytes();
    };

    // ========== МОНИТОРИНГ СИСТЕМНОГО ВРЕМЕНИ ==========
    
    try {
        var System = Java.use("java.lang.System");
        System.currentTimeMillis.implementation = function() {
            var time = this.currentTimeMillis();
            console.log("[+] System time requested: " + time + " (" + Math.floor(time/1000) + ")");
            return time;
        };
    } catch(e) {}

    console.log("[+] Все перехватчики установлены!");
});

// ========== НАТИВНЫЕ ФУНКЦИИ ==========

// Перехват нативных crypto функций
Interceptor.attach(Module.findExportByName("libc.so", "time"), {
    onEnter: function(args) {
        console.log("[+] Native time() called");
    },
    onLeave: function(retval) {
        console.log("[+] Native time() result: " + retval);
    }
});

// Поиск HMAC функций в нативных библиотеках
var hmac_libs = ["libcrypto.so", "libssl.so"];
hmac_libs.forEach(function(lib) {
    try {
        var hmac_init = Module.findExportByName(lib, "HMAC_Init_ex");
        if (hmac_init) {
            Interceptor.attach(hmac_init, {
                onEnter: function(args) {
                    console.log("[+] Native HMAC_Init_ex called");
                    // args[1] - key, args[2] - key length
                    if (args[1] && args[2]) {
                        var keyLen = args[2].toInt32();
                        if (keyLen > 0 && keyLen < 1024) {
                            var key = Memory.readUtf8String(args[1], keyLen);
                            console.log("[+] Native HMAC key: '" + key + "'");
                        }
                    }
                }
            });
        }
    } catch(e) {}
});

// ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========

function bytesToHex(bytes) {
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
        hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}

function hexToString(hex) {
    var str = "";
    for (var i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
}

// Периодический вывод найденных ключей
setInterval(function() {
    if (foundKeys.length > 0) {
        console.log("\n[=] SUMMARY - Found " + foundKeys.length + " potential keys:");
        foundKeys.forEach(function(item, index) {
            console.log("  [" + index + "] Type: " + item.type + 
                       (item.key ? ", Key: '" + item.key + "'" : "") +
                       (item.bytes ? ", Bytes: " + item.bytes : "") +
                       (item.token ? ", Token: " + item.token.substring(0, 50) + "..." : ""));
        });
        console.log("[=] END SUMMARY\n");
    }
}, 10000); // Каждые 10 секунд
