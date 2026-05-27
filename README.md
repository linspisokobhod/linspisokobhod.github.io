# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-05-27 14:02:33`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `59947` |
| 📱 **LTE.txt** | `59947` |
| 📶 **WiFi.txt** | `53773` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `53216` |
| 📦 VMess | `702` |
| 🛡️ Trojan | `5942` |
| ⚡ Hysteria2 | `87` |

## 🗂️ Логика LTE.txt

1. **Приоритет 1**: sni домен из `whitelist.txt`
2. **Приоритет 2**: IP сервера входит в CIDR из `cidrwhitelist.txt`
3. **Приоритет 3**: остальные конфиги

## 📋 Источники белых списков

Файлы `whitelist.txt` и `cidrwhitelist.txt` взяты из репозитория:
🔗 [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist)

## 📁 Файлы

- `configs/all.txt` – все конфиги
- `configs/LTE.txt` – отсортированные по приоритету
- `configs/WiFi.txt` – остальные

## 🔄 Автообновление

Скрипт запускается **каждый час**.

---
*LinSpisokObhod v1*
