# 🚀 LinSpisokObhod

## 📅 Время последнего сбора
`2026-04-25 09:41:01`

## 📊 Статистика конфигов

| Файл | Количество |
|------|------------|
| 📁 **all.txt** | `43802` |
| 📱 **LTE.txt** (домен + IP в белых списках) | `0` |
| 📶 **WiFi.txt** (остальные) | `43802` |

## 📡 Распределение по протоколам

| Протокол | Количество |
|----------|------------|
| 🔗 **VLESS** | `37780` |
| 📦 **VMess** | `2806` |
| 🛡️ **Trojan** | `3216` |

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
- **WiFi.txt**: все остальные конфиги

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
Последнее обновление: `2026-04-25 09:41:01`

---
*Сгенерировано автоматически VPN Config Collector v12.1*
