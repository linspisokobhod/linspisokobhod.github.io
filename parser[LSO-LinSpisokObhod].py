#!/usr/bin/env python3
"""
VPN Config Collector v12.0 (LSO-LinSpisokObhod)
- Единая маркировка [LSO-LinSpisokObhod]
- Формирование имени: домен (sni) + тип (WebSocket/другое)
- Сбор ss://, vless://, vmess://, trojan://
- Дедупликация конфигов
- LTE: домен в whitelist.txt И IP в whitelist.ip.txt
- SS всегда дублируются в LTE.txt и WiFi.txt
- Автообновление README.md
- Только all.txt, LTE.txt, WiFi.txt
- Белые списки в папке lists/
"""

import os
import re
import json
import time
import logging
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs
from typing import Dict, Set, Optional
import base64

# ========== НАСТРОЙКИ ==========
SOURCES = [
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mehdirzfx/v2ray-sub/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/all_configs.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://raw.githubusercontent.com/yaney01/telegram-collector/main/protocols/vless",
    "https://raw.githubusercontent.com/yaney01/telegram-collector/main/channels/protocols/vless",
    "https://raw.githubusercontent.com/yaney01/telegram-collector/main/protocols/vmess",
    "https://raw.githubusercontent.com/yaney01/telegram-collector/main/channels/protocols/vmess",
    "https://raw.githubusercontent.com/yaney01/telegram-collector/main/protocols/trojan",
    "https://raw.githubusercontent.com/yaney01/telegram-collector/main/channels/protocols/trojan",
    "https://raw.githubusercontent.com/yaney01/telegram-collector/main/protocols/shadowsocks",
    "https://raw.githubusercontent.com/yaney01/telegram-collector/main/channels/protocols/shadowsocks",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/all.txt",
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/configs/url_work.txt",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/1",
]

GLOBAL_TAG = "[LSO-LinSpisokObhod]"
SCRIPT_NAME = "parser[LSO-LinSpisokObhod].py"

PROTOCOL_PATTERNS = {
    'ss': re.compile(r'ss://[A-Za-z0-9+/=@:;,\?&%#\.\-_~!$*()]+', re.IGNORECASE),
    'vless': re.compile(r'vless://[A-Za-z0-9+/=@:;,\?&%#\.\-_~!$*()]+', re.IGNORECASE),
    'vmess': re.compile(r'vmess://[A-Za-z0-9+/=]+', re.IGNORECASE),
    'trojan': re.compile(r'trojan://[A-Za-z0-9+/=@:;,\?&%#\.\-_~!$*()]+', re.IGNORECASE),
}

REQUEST_TIMEOUT = 30
MAX_WORKERS = 10
CONFIG_DIR = "configs"
LISTS_DIR = "lists"
LOG_FILE = "collector.log"
WHITELIST_FILE = os.path.join(LISTS_DIR, "whitelist.txt")
WHITELIST_IP_FILE = os.path.join(LISTS_DIR, "whitelist.ip.txt")
README_FILE = "README.md"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ----------
def fetch_url_content(url: str) -> Optional[str]:
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status()
        if 'charset' in response.headers.get('content-type', '').lower():
            content = response.text
        else:
            try:
                content = response.content.decode('utf-8')
            except UnicodeDecodeError:
                content = response.content.decode('utf-8', errors='ignore')
        logger.info(f"✅ Загружен {url} ({len(content)} символов)")
        return content
    except Exception as e:
        logger.warning(f"⚠️ Ошибка загрузки {url}: {e}")
        return None

def extract_configs_from_text(text: str, source_url: str) -> Dict[str, Set[str]]:
    configs = {proto: set() for proto in PROTOCOL_PATTERNS}
    for protocol, pattern in PROTOCOL_PATTERNS.items():
        matches = pattern.findall(text)
        for match in matches:
            if 50 < len(match) < 5000:
                configs[protocol].add(match)
        if matches:
            logger.debug(f"Найдено {len(matches)} конфигураций {protocol} в {source_url}")
    return configs

def decode_vmess_config(config: str) -> Optional[Dict]:
    try:
        if config.startswith('vmess://'):
            encoded = config[8:]
            decoded = base64.b64decode(encoded).decode('utf-8')
            return json.loads(decoded)
    except Exception:
        pass
    return None

def validate_config(config: str, protocol: str) -> bool:
    if len(config) < 20:
        return False
    if protocol == 'vmess':
        decoded = decode_vmess_config(config)
        if decoded:
            required_fields = ['v', 'ps', 'add', 'port', 'id']
            return all(field in decoded for field in required_fields)
        return False
    if protocol == 'ss':
        return '@' in config or ':' in config
    elif protocol == 'vless':
        return 'encryption=' in config or 'security=' in config or '@' in config
    elif protocol == 'trojan':
        return '@' in config or 'password' in config or 'sni' in config
    return True

def extract_sni_domain(config: str) -> Optional[str]:
    protocol = None
    for p in PROTOCOL_PATTERNS:
        if config.startswith(p + "://"):
            protocol = p
            break
    if not protocol:
        return None

    body = config[len(protocol)+3:]
    
    if protocol == 'vless':
        if '?' in body:
            query_part = body.split('?', 1)[1]
            params = parse_qs(query_part)
            if 'sni' in params:
                return params['sni'][0]
        if '@' in body:
            host_part = body.split('@')[1]
            host = host_part.split(':')[0]
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
                return host
        return None
    
    if protocol == 'trojan':
        if '?' in body:
            query_part = body.split('?', 1)[1]
            params = parse_qs(query_part)
            if 'sni' in params:
                return params['sni'][0]
        if '@' in body:
            host_part = body.split('@')[1]
            host = host_part.split(':')[0]
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
                return host
        return None
    
    if protocol == 'vmess':
        decoded = decode_vmess_config(config)
        if decoded and 'add' in decoded:
            addr = decoded['add']
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', addr):
                return addr
        return None
    
    return None

def extract_type_from_config(config: str) -> str:
    protocol = None
    for p in PROTOCOL_PATTERNS:
        if config.startswith(p + "://"):
            protocol = p
            break
    if not protocol:
        return "unknown"
    
    body = config[len(protocol)+3:]
    
    if '?' in body:
        query_part = body.split('?', 1)[1]
        params = parse_qs(query_part)
        if 'type' in params:
            t = params['type'][0].lower()
            if t == 'ws':
                return "WebSocket"
            return t.upper()
    
    return "unknown"

def rename_config(config: str) -> str:
    protocol = None
    for p in PROTOCOL_PATTERNS:
        if config.startswith(p + "://"):
            protocol = p
            break
    if not protocol:
        return config
    
    sni_domain = extract_sni_domain(config)
    conn_type = extract_type_from_config(config)
    
    if ' #' in config:
        config = config.split(' #')[0]
    
    if sni_domain:
        new_name = f" # {sni_domain} | {conn_type}"
    else:
        new_name = f" # unknown | {conn_type}"
    
    return config + new_name

def extract_domain_from_config(config: str) -> Optional[str]:
    return extract_sni_domain(config)

def extract_ip_from_config(config: str) -> Optional[str]:
    protocol = None
    for p in PROTOCOL_PATTERNS:
        if config.startswith(p + "://"):
            protocol = p
            break
    if not protocol:
        return None

    body = config[len(protocol)+3:]

    if protocol == 'vmess':
        decoded = decode_vmess_config(config)
        if decoded and 'add' in decoded:
            addr = decoded['add']
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', addr):
                return addr
        return None

    if protocol == 'vless':
        if '?' in body:
            query_part = body.split('?', 1)[1]
            params = parse_qs(query_part)
            for key in ('sni', 'add', 'host'):
                if key in params and params[key][0]:
                    val = params[key][0]
                    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', val):
                        return val
        if '@' in body:
            host_part = body.split('@')[1]
            host = host_part.split(':')[0]
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
                return host
        return None

    if protocol in ('ss', 'trojan'):
        if '@' in body:
            host_part = body.split('@')[1]
            host = host_part.split(':')[0]
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
                return host
        if protocol == 'trojan' and '?' in body:
            query_part = body.split('?', 1)[1]
            params = parse_qs(query_part)
            if 'sni' in params:
                sni_val = params['sni'][0]
                if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', sni_val):
                    return sni_val
        return None

    return None

def ensure_lists_dir():
    if not os.path.exists(LISTS_DIR):
        os.makedirs(LISTS_DIR)
        logger.info(f"📁 Создана папка {LISTS_DIR}")

def load_whitelist() -> Set[str]:
    ensure_lists_dir()
    whitelist = set()
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'w', encoding='utf-8') as f:
            f.write("# Домены для LTE (один на строку)\n")
            f.write("example.com\n")
        logger.info(f"📝 Создан пример {WHITELIST_FILE} — отредактируйте его")
        return whitelist
    with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                whitelist.add(line)
    logger.info(f"📋 Загружено {len(whitelist)} доменов из {WHITELIST_FILE}")
    return whitelist

def load_ip_whitelist() -> Set[str]:
    ensure_lists_dir()
    ip_whitelist = set()
    if not os.path.exists(WHITELIST_IP_FILE):
        with open(WHITELIST_IP_FILE, 'w', encoding='utf-8') as f:
            f.write("# IP-адреса для LTE (один на строку)\n")
            f.write("1.1.1.1\n")
            f.write("8.8.8.8\n")
        logger.info(f"📝 Создан пример {WHITELIST_IP_FILE} — отредактируйте его")
        return ip_whitelist
    with open(WHITELIST_IP_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                ip_whitelist.add(line)
    logger.info(f"📋 Загружено {len(ip_whitelist)} IP из {WHITELIST_IP_FILE}")
    return ip_whitelist

def classify_config(config: str, whitelist_domains: Set[str], whitelist_ips: Set[str]) -> str:
    protocol = None
    for p in PROTOCOL_PATTERNS:
        if config.startswith(p + "://"):
            protocol = p
            break

    if protocol == 'ss':
        return 'both'

    domain = extract_domain_from_config(config)
    ip = extract_ip_from_config(config)

    if domain and ip and domain in whitelist_domains and ip in whitelist_ips:
        return 'lte'
    return 'wifi'

def collect_configs() -> Set[str]:
    all_configs_set = set()
    logger.info(f"🚀 Начинаю сбор из {len(SOURCES)} источников...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(fetch_url_content, url): url for url in SOURCES}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            content = future.result()
            if not content:
                continue

            configs_by_proto = extract_configs_from_text(content, url)

            for protocol, config_set in configs_by_proto.items():
                valid_configs = {cfg for cfg in config_set if validate_config(cfg, protocol)}
                if not valid_configs:
                    continue
                logger.info(f"📥 +{len(valid_configs)} {protocol.upper()} из {url}")
                for cfg in valid_configs:
                    renamed_cfg = rename_config(cfg)
                    all_configs_set.add(renamed_cfg)
    
    return all_configs_set

def get_protocol_from_config(config: str) -> str:
    for protocol in PROTOCOL_PATTERNS:
        if config.startswith(protocol + "://"):
            return protocol
    return "unknown"

def update_readme(stats: Dict, sources_count: int):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    readme_content = (
        "# 🚀 LinSpisokObhod\n\n"
        "## 📅 Время последнего сбора\n"
        f"`{now}`\n\n"
        "## 📊 Статистика конфигов\n\n"
        "| Файл | Количество |\n"
        "|------|------------|\n"
        f"| 📁 **all.txt** | `{stats['total_configs']}` |\n"
        f"| 📱 **LTE.txt** (домен + IP в белых списках) | `{stats['filtered']['lte']}` |\n"
        f"| 📶 **WiFi.txt** (остальные) | `{stats['filtered']['wifi']}` |\n\n"
        "## 📡 Распределение по протоколам\n\n"
        "| Протокол | Количество |\n"
        "|----------|------------|\n"
        f"| 🔗 **VLESS** | `{stats['by_protocol'].get('vless', 0)}` |\n"
        f"| 📦 **VMess** | `{stats['by_protocol'].get('vmess', 0)}` |\n"
        f"| 🛡️ **Trojan** | `{stats['by_protocol'].get('trojan', 0)}` |\n"
        f"| 🌊 **Shadowsocks** | `{stats['by_protocol'].get('ss', 0)}` |\n\n"
        "## 📋 Источники (всего: {sources_count})\n\n"
        "Конфиги собираются из следующих публичных репозиториев:\n"
        "- Epodonios, barry-far, mehdirzfx, Delta-Kronecker\n"
        "- V2RayRoot, sevcator, yaney01\n"
        "- sakha1370, roosterkid, yitong2333\n"
        "- Hidashimora, 4n0nymou3\n"
        "- RKPchannel\n"
        "- EtoNeYaProject\n\n"
        "## 🏷️ Маркировка\n\n"
        f"Все конфиги имеют единую метку: `{GLOBAL_TAG}`\n\n"
        "## 📝 Формат именования конфигов\n\n"
        "```\nпротокол://... # домен_из_sni | тип_подключения\n```\n\n"
        "Пример: `vless://uuid@ip:port?... # example.com | WebSocket`\n\n"
        "## ⚙️ Логика фильтрации\n\n"
        "- **LTE.txt**: конфиг попадает сюда, если его **домен** есть в `lists/whitelist.txt` **И** **IP-адрес** есть в `lists/whitelist.ip.txt`\n"
        "- **WiFi.txt**: все остальные конфиги (включая все `ss://`)\n"
        "- `ss://` конфиги дублируются в оба файла\n\n"
        "## 📁 Структура выходных файлов\n\n"
        "```\n├── configs/\n│   ├── all.txt\n│   ├── LTE.txt\n│   ├── WiFi.txt\n│   └── stats.json\n├── lists/\n│   ├── whitelist.txt\n│   └── whitelist.ip.txt\n└── README.md\n```\n\n"
        "## 🔄 Автообновление\n\n"
        f"Скрипт `{SCRIPT_NAME}` может запускаться по расписанию (например, через GitHub Actions).\n"
        f"Последнее обновление: `{now}`\n\n"
        "---\n*Сгенерировано автоматически VPN Config Collector v12.0*\n"
    )
    with open(README_FILE, 'w', encoding='utf-8') as f:
        f.write(readme_content)
    logger.info("📄 README.md обновлён")

def save_configs(all_configs_set: Set[str]):
    os.makedirs(CONFIG_DIR, exist_ok=True)

    tagged_set = {f"{cfg} {GLOBAL_TAG}" for cfg in all_configs_set}

    all_txt_path = os.path.join(CONFIG_DIR, "all.txt")
    with open(all_txt_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(sorted(tagged_set)) + "\n")
    logger.info(f"💾 Общий файл {all_txt_path} ({len(tagged_set)} уникальных конфигов)")

    whitelist_domains = load_whitelist()
    whitelist_ips = load_ip_whitelist()
    lte_set = set()
    wifi_set = set()

    for line in tagged_set:
        clean_line = line.replace(f" {GLOBAL_TAG}", "")
        cat = classify_config(clean_line, whitelist_domains, whitelist_ips)
        if cat == 'lte':
            lte_set.add(line)
        elif cat == 'wifi':
            wifi_set.add(line)
        elif cat == 'both':
            lte_set.add(line)
            wifi_set.add(line)

    lte_path = os.path.join(CONFIG_DIR, "LTE.txt")
    with open(lte_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(sorted(lte_set)) + "\n")
    logger.info(f"📱 LTE: {len(lte_set)} уникальных конфигов -> {lte_path}")

    wifi_path = os.path.join(CONFIG_DIR, "WiFi.txt")
    with open(wifi_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(sorted(wifi_set)) + "\n")
    logger.info(f"📶 WiFi: {len(wifi_set)} уникальных конфигов -> {wifi_path}")

    protocol_stats = {proto: 0 for proto in PROTOCOL_PATTERNS}
    for cfg in all_configs_set:
        proto = get_protocol_from_config(cfg)
        if proto in protocol_stats:
            protocol_stats[proto] += 1

    stats = {
        "timestamp": datetime.now().isoformat(),
        "total_configs": len(tagged_set),
        "by_protocol": protocol_stats,
        "filtered": {"lte": len(lte_set), "wifi": len(wifi_set)}
    }
    stats_path = os.path.join(CONFIG_DIR, "stats.json")
    with open(stats_path, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    logger.info(f"📊 Статистика сохранена в {stats_path}")
    
    update_readme(stats, len(SOURCES))
    return stats

def main():
    start_time = time.time()
    print("=" * 60)
    print(f"🚀 {SCRIPT_NAME} v12.0 (LSO-LinSpisokObhod)")
    print("=" * 60)
    print(f"📋 Источников: {len(SOURCES)}")
    print(f"🔄 Протоколы: {', '.join(PROTOCOL_PATTERNS.keys())}")
    print(f"📄 Whitelist доменов: {WHITELIST_FILE}")
    print(f"🌐 Whitelist IP: {WHITELIST_IP_FILE}")
    print(f"🏷️  Маркировка: {GLOBAL_TAG}")
    print("=" * 60)

    all_configs = collect_configs()
    stats = save_configs(all_configs)

    elapsed = time.time() - start_time
    print("\n" + "=" * 60)
    print("📊 ИТОГИ СБОРА:")
    print("=" * 60)
    print(f"📈 Всего уникальных конфигураций: {stats['total_configs']}")
    print(f"   📱 LTE (домен И IP в whitelist): {stats['filtered']['lte']}")
    print(f"   📶 WiFi (остальные + все SS): {stats['filtered']['wifi']}")
    for proto, count in stats['by_protocol'].items():
        if count:
            print(f"   {proto.upper()}: {count}")
    print(f"⏱️ Время выполнения: {elapsed:.2f} секунд")
    print(f"📁 Результаты в папке '{CONFIG_DIR}/'")
    print(f"📁 Белые списки в папке '{LISTS_DIR}/'")
    print(f"📄 README.md обновлён")
    print("=" * 60)

    logger.info(f"✅ Сбор завершен: {stats['total_configs']} уникальных конфигов за {elapsed:.2f}с")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("⏹️ Прерывание")
    except Exception as e:
        logger.error(f"❌ Ошибка: {e}")
        raise
