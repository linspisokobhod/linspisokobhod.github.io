# 🚀 LinSpisokObhod

## 📅 Время последнего сбора

`2026-08-31 16:29:48 (UTC+3)`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 ALL.txt / ALL.64.txt | `450` |
| 📱 LTE.txt / LTE.64.txt | `26` |
| 📶 WIFI.txt / WIFI.64.txt | `424` |
| 🏫 LinObhodESPD.txt / LinObhodESPD.64.txt | `7` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `414` |
| 📦 VMess | `0` |
| 🛡️ Trojan | `25` |
| ⚡ Hysteria2 | `11` |

## 🗂️ Логика LTE.txt

1. **Приоритет 1**: sni домен из `whitelist.txt`
2. **Приоритет 2**: IP сервера входит в CIDR из `cidrwhitelist.txt`
3. **WIFI.txt**: все остальные конфиги

## 📁 Файлы

- `sub/ALL.txt` – все конфиги (обычный текст)
- `sub/ALL.64.txt` – все конфиги, закодированные в base64
- `sub/LTE.txt` – отфильтрованные по whitelist/CIDR (обычный текст)
- `sub/LTE.64.txt` – отфильтрованные, закодированные в base64
- `sub/WIFI.txt` – остальные конфиги (обычный текст)
- `sub/WIFI.64.txt` – остальные, закодированные в base64
- `sub/LinObhodESPD.txt` – конфиги с SNI max.ru или api-maps.yandex.ru (обычный текст)
- `sub/LinObhodESPD.64.txt` – конфиги с SNI max.ru или api-maps.yandex.ru (base64)

## 🔄 Автообновление

Скрипт запускается **каждый час**.

---
*LinSpisokObhod v3.8*
