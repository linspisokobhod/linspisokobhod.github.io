# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-06-07 16:29:11`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `5302` |
| 📱 **LTE.txt** | `1161` |
| 📶 **WiFi.txt** | `4141` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `4102` |
| 📦 VMess | `133` |
| 🛡️ Trojan | `905` |
| ⚡ Hysteria2 | `162` |

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
