# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-06-06 10:17:38`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `4917` |
| 📱 **LTE.txt** | `1066` |
| 📶 **WiFi.txt** | `3851` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `3753` |
| 📦 VMess | `143` |
| 🛡️ Trojan | `874` |
| ⚡ Hysteria2 | `147` |

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
