# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-05-29 17:00:12`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `8679` |
| 📱 **LTE.txt** | `1521` |
| 📶 **WiFi.txt** | `7158` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `6022` |
| 📦 VMess | `134` |
| 🛡️ Trojan | `2421` |
| ⚡ Hysteria2 | `102` |

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
