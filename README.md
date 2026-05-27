# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-05-27 15:21:34`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `66848` |
| 📱 **LTE.txt** | `6233` |
| 📶 **WiFi.txt** | `60615` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `58073` |
| 📦 VMess | `1474` |
| 🛡️ Trojan | `7174` |
| ⚡ Hysteria2 | `127` |

## 🗂️ Логика LTE.txt

1. **Приоритет 1**: sni домен из `whitelist.txt`
2. **Приоритет 2**: IP сервера входит в CIDR из `cidrwhitelist.txt`
3. **WiFi.txt**: все остальные конфиги

## 📋 Источники белых списков

Файлы `whitelist.txt` и `cidrwhitelist.txt` взяты из репозитория:
🔗 [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist)

## 📁 Файлы

- `sub/all.txt` – все конфиги
- `sub/LTE.txt` – отфильтрованные по whitelist/CIDR и отсортированные
- `sub/WiFi.txt` – остальные

## 🔄 Автообновление

Скрипт запускается **каждый час**.

---
*LinSpisokObhod v1.8*
