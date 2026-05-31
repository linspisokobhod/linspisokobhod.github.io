# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-05-31 23:14:40`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `6233` |
| 📱 **LTE.txt** | `1324` |
| 📶 **WiFi.txt** | `4909` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `4965` |
| 📦 VMess | `132` |
| 🛡️ Trojan | `1011` |
| ⚡ Hysteria2 | `125` |

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
