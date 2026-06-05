# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-06-05 21:45:16`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `5019` |
| 📱 **LTE.txt** | `1043` |
| 📶 **WiFi.txt** | `3976` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `3804` |
| 📦 VMess | `143` |
| 🛡️ Trojan | `920` |
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
