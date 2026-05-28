# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-05-28 07:38:48`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `8254` |
| 📱 **LTE.txt** | `1246` |
| 📶 **WiFi.txt** | `7008` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `5582` |
| 📦 VMess | `123` |
| 🛡️ Trojan | `2439` |
| ⚡ Hysteria2 | `110` |

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
*LinSpisokObhod v1.13*
