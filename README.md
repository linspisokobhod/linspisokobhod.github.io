# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-05-27 22:46:19`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `9131` |
| 📱 **LTE.txt** | `1548` |
| 📶 **WiFi.txt** | `7583` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `6332` |
| 📦 VMess | `136` |
| 🛡️ Trojan | `2555` |
| ⚡ Hysteria2 | `108` |

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
*LinSpisokObhod v1.12*
