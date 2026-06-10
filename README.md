# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-06-10 04:24:37`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `5535` |
| 📱 **LTE.txt** | `1311` |
| 📶 **WiFi.txt** | `4224` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `4429` |
| 📦 VMess | `143` |
| 🛡️ Trojan | `813` |
| ⚡ Hysteria2 | `150` |

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
