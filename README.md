# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-06-03 10:05:31`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `5170` |
| 📱 **LTE.txt** | `1117` |
| 📶 **WiFi.txt** | `4053` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `4046` |
| 📦 VMess | `118` |
| 🛡️ Trojan | `864` |
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
