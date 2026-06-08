# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-06-08 11:23:16`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `8090` |
| 📱 **LTE.txt** | `3012` |
| 📶 **WiFi.txt** | `5078` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `6975` |
| 📦 VMess | `138` |
| 🛡️ Trojan | `825` |
| ⚡ Hysteria2 | `152` |

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
