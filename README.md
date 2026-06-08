# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-06-08 06:04:24`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `8347` |
| 📱 **LTE.txt** | `3089` |
| 📶 **WiFi.txt** | `5258` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `7213` |
| 📦 VMess | `139` |
| 🛡️ Trojan | `839` |
| ⚡ Hysteria2 | `156` |

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
