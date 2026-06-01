# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-06-01 23:15:08`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `7045` |
| 📱 **LTE.txt** | `1473` |
| 📶 **WiFi.txt** | `5572` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `5716` |
| 📦 VMess | `153` |
| 🛡️ Trojan | `1034` |
| ⚡ Hysteria2 | `142` |

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
*LinSpisokObhod v3.8*
