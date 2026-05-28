# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-05-28 10:36:34`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `8256` |
| 📱 **LTE.txt** | `1308` |
| 📶 **WiFi.txt** | `6948` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `5588` |
| 📦 VMess | `125` |
| 🛡️ Trojan | `2432` |
| ⚡ Hysteria2 | `111` |

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
*LinSpisokObhod v2.8*
