# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-05-27 15:12:53`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `66860` |
| 📱 **LTE.txt** | `66860` |
| 📶 **WiFi.txt** | `60616` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `58085` |
| 📦 VMess | `1474` |
| 🛡️ Trojan | `7174` |
| ⚡ Hysteria2 | `127` |

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
*LinSpisokObhod v1.5*
