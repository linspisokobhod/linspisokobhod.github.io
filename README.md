# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-06-05 23:21:58`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `5052` |
| 📱 **LTE.txt** | `1064` |
| 📶 **WiFi.txt** | `3988` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `3838` |
| 📦 VMess | `143` |
| 🛡️ Trojan | `920` |
| ⚡ Hysteria2 | `151` |

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
