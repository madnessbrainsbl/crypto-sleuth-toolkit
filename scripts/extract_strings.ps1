# Извлечение строк из бинарного файла unlock
param(
    [string]$FilePath = "unlock",
    [int]$MinLength = 4
)

if (-not (Test-Path $FilePath)) {
    Write-Host "Файл $FilePath не найден"
    exit 1
}

# Читаем файл как массив байт
$bytes = [System.IO.File]::ReadAllBytes($FilePath)

# Извлекаем ASCII строки
$currentString = ""
$strings = @()

foreach ($byte in $bytes) {
    if ($byte -ge 32 -and $byte -le 126) {  # Printable ASCII
        $currentString += [char]$byte
    } else {
        if ($currentString.Length -ge $MinLength) {
            $strings += $currentString
        }
        $currentString = ""
    }
}

# Добавляем последнюю строку если нужно
if ($currentString.Length -ge $MinLength) {
    $strings += $currentString
}

# Выводим интересные строки
Write-Host "=== Все строки (первые 100) ==="
$strings | Select-Object -First 100 | ForEach-Object { Write-Host $_ }

Write-Host "`n=== Потенциальные ключи/секреты ==="
$strings | Where-Object { 
    $_ -match "(key|secret|token|pass|auth|sign|hmac|jwt|unlock|cunba)" -or
    $_ -match "^[A-Za-z0-9+/]{20,}={0,2}$" -or  # Base64
    $_ -match "^[0-9a-fA-F]{32,}$"               # Hex
} | ForEach-Object { Write-Host "POTENTIAL KEY: $_" }

Write-Host "`n=== URL и сетевые адреса ==="
$strings | Where-Object { 
    $_ -match "http|ftp|tcp|udp|://|@" 
} | ForEach-Object { Write-Host "NETWORK: $_" }

Write-Host "`n=== Возможные функции JWT ==="
$strings | Where-Object { 
    $_ -match "(jwt|json|token|header|payload|signature|alg|iss|exp|iat|nbf)" 
} | ForEach-Object { Write-Host "JWT RELATED: $_" }
