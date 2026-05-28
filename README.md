# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-05-28 07:45:44`

## 📊 Статистика

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `16833` |
| 📱 **LTE.txt** | `2043` |
| 📶 **WiFi.txt** | `14790` |

## 📡 Протоколы

| Протокол | Количество |
|----------|------------|
| 🔗 VLESS | `5711` |
| 📦 VMess | `123` |
| 🛡️ Trojan | `2540` |
| ⚡ Hysteria2 | `120` |
| 🌊 Shadowsocks | `8339` |

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
*LinSpisokObhod v1.14*
