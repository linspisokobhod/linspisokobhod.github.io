# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-06-04 16:30:44`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `5192` |
| 📱 **LTE.txt** | `1159` |
| 📶 **WiFi.txt** | `4033` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `4031` |
| 📦 VMess | `126` |
| 🛡️ Trojan | `900` |
| ⚡ Hysteria2 | `135` |

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
