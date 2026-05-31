# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-05-31 04:31:39`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `6476` |
| 📱 **LTE.txt** | `1510` |
| 📶 **WiFi.txt** | `4966` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `5248` |
| 📦 VMess | `127` |
| 🛡️ Trojan | `1006` |
| ⚡ Hysteria2 | `95` |

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
