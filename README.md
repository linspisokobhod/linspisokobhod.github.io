# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-04-25 09:23:24`

## 📊 Статистика конфигов

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `87899` |
| 📱 **LTE.txt** (домен + IP в белых списках) | `44377` |
| 📶 **WiFi.txt** (остальные) | `87899` |

## 📡 Распределение по протоколам

| Протокол | Количество |
|----------|------------|
| 🔗 **VLESS** | `37545` |
| 📦 **VMess** | `2818` |
| 🛡️ **Trojan** | `3159` |
| 🌊 **Shadowsocks** | `44377` |

## 📋 Источники (всего: {sources_count})

Конфиги собираются из следующих публичных репозиториев:
- Epodonios, barry-far, mehdirzfx, Delta-Kronecker
- V2RayRoot, sevcator, yaney01
- sakha1370, roosterkid, yitong2333
- Hidashimora, 4n0nymou3
- RKPchannel
- EtoNeYaProject

## 🏷️ Маркировка

Все конфиги имеют единую метку: `[LSO-LinSpisokObhod]`

## 📝 Формат именования конфигов

```
протокол://... # домен_из_sni | тип_подключения
```

Пример: `vless://uuid@ip:port?... # example.com | WebSocket`

## ⚙️ Логика фильтрации

- **LTE.txt**: конфиг попадает сюда, если его **домен** есть в `lists/whitelist.txt` **И** **IP-адрес** есть в `lists/whitelist.ip.txt`
- **WiFi.txt**: все остальные конфиги (включая все `ss://`)
- `ss://` конфиги дублируются в оба файла

## 📁 Структура выходных файлов

```
├── configs/
│   ├── all.txt
│   ├── LTE.txt
│   ├── WiFi.txt
│   └── stats.json
├── lists/
│   ├── whitelist.txt
│   └── whitelist.ip.txt
└── README.md
```

## 🔄 Автообновление

Скрипт `parser[LSO-LinSpisokObhod].py` может запускаться по расписанию (например, через GitHub Actions).
Последнее обновление: `2026-04-25 09:23:24`

---
*Сгенерировано автоматически VPN Config Collector v12.0*
