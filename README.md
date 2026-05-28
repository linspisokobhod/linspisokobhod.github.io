# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-05-28 11:55:48`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `8196` |
| 📱 **LTE.txt** | `1245` |
| 📶 **WiFi.txt** | `6951` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `5532` |
| 📦 VMess | `126` |
| 🛡️ Trojan | `2429` |
| ⚡ Hysteria2 | `109` |

## 🗂️ Логика LTE.txt

1. **Приоритет 1**: sni домен из `whitelist.txt`
2. **Приоритет 2**: IP сервера входит в CIDR из `cidrwhitelist.txt`
3. **WiFi.txt**: все остальные конфиги

## 📋 Источники белых списков

Файлы `whitelist.txt` и `cidrwhitelist.txt` взяты из репозитория:
🔗 [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist)

## 📁 Файлы

- `sub/all.txt` – все конфиги (геолокация только для IP, для доменов – unknown)
- `sub/LTE.txt` – отфильтрованные по whitelist/CIDR и отсортированные
- `sub/WiFi.txt` – остальные

## 🔄 Автообновление

Скрипт запускается **каждый час**.

---
*LinSpisokObhod v3.2*
