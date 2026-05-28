# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-05-28 05:14:17`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `9145` |
| 📱 **LTE.txt** | `1577` |
| 📶 **WiFi.txt** | `7568` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `6426` |
| 📦 VMess | `138` |
| 🛡️ Trojan | `2475` |
| ⚡ Hysteria2 | `106` |

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
