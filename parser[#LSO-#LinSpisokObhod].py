#!/usr/bin/env python3

import os
import re
import json
import time
import logging
import ipaddress
import shutil
import asyncio
import aiohttp
from datetime import datetime
from urllib.parse import parse_qs
from typing import Dict, Set, Optional, List
import base64

# ========== НАСТРОЙКИ ==========
ENABLE_GEOIP = True          # Геолокация включена
GEOIP_CACHE = {}

SOURCES = [
    "https://alley.serv00.net/1",
    "https://raw.githubusercontent.com/tahmaseb73/Telegram_config_collector/refs/heads/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/v0id9/vpn-configs/refs/heads/main/vpn.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://gist.githubusercontent.com/DestroyST6767/50af50221ca1858ba2084efc0f524fbc/raw",
    "https://rostunnel.vercel.app/mega.txt",
    "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/hysteria2_001.txt",
    "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/hy2_001.txt",
]

GLOBAL_TAG = "[#LSO - #LinSpisokObhod]"
SCRIPT_NAME = "LinSpisokObhod.py"

PROTOCOL_PATTERNS = {
    'vless': re.compile(r'vless://[A-Za-z0-9+/=@:;,\?&%#\.\-_~!$*()]+', re.IGNORECASE),
    'vmess': re.compile(r'vmess://[A-Za-z0-9+/=]+', re.IGNORECASE),
    'trojan': re.compile(r'trojan://[A-Za-z0-9+/=@:;,\?&%#\.\-_~!$*()]+', re.IGNORECASE),
    'hysteria2': re.compile(r'hysteria2://[A-Za-z0-9+/=@:;,\?&%#\.\-_~!$*()]+', re.IGNORECASE),
}

REQUEST_TIMEOUT = 100
MAX_WORKERS = 100
CONFIG_DIR = "sub"
LISTS_DIR = "lists"
LOG_FILE = "collector.log"
WHITELIST_FILE = os.path.join(LISTS_DIR, "whitelist.txt")
CIDR_WHITELIST_FILE = os.path.join(LISTS_DIR, "cidrwhitelist.txt")
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

# ---------- АСИНХРОННАЯ ЗАГРУЗКА ----------
async def fetch_url_content(session: aiohttp.ClientSession, url: str) -> Optional[str]:
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        async with session.get(url, timeout=REQUEST_TIMEOUT, headers=headers) as response:
            if response.status == 200:
                content = await response.text()
                logger.info(f"✅ Загружен {url} ({len(content)} символов)")
                return content
            else:
                logger.warning(f"⚠️ Ошибка {response.status} при загрузке {url}")
    except Exception as e:
        logger.warning(f"⚠️ Ошибка загрузки {url}: {e}")
    return None

async def fetch_all_sources():
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_url_content(session, url) for url in SOURCES]
        results = await asyncio.gather(*tasks)
    return dict(zip(SOURCES, results))

# ---------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ----------
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
        if decoded and all(k in decoded for k in ('v', 'ps', 'add', 'port', 'id')):
            return True
        return False
    elif protocol == 'vless':
        sni = extract_sni_domain(config)
        ip = extract_ip_from_config(config)
        if not (sni or ip):
            return False
        return 'encryption=' in config or 'security=' in config or '@' in config
    elif protocol == 'trojan':
        sni = extract_sni_domain(config)
        ip = extract_ip_from_config(config)
        if not (sni or ip):
            return False
        return '@' in config or 'password' in config or 'sni' in config
    elif protocol == 'hysteria2':
        ip = extract_ip_from_config(config)
        sni = extract_sni_domain(config)
        if not (ip or sni):
            return False
        return '@' in config
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
    
    if protocol in ('vless', 'trojan', 'hysteria2'):
        if '?' in body:
            query_part = body.split('?', 1)[1]
            params = parse_qs(query_part)
            if 'sni' in params:
                return params['sni'][0]
        return None
    
    if protocol == 'vmess':
        decoded = decode_vmess_config(config)
        if decoded and 'add' in decoded:
            return decoded['add']
        return None
    
    return None

def extract_ip_from_config(config: str) -> Optional[str]:
    protocol = None
    for p in PROTOCOL_PATTERNS:
        if config.startswith(p + "://"):
            protocol = p
            break
    if not protocol:
        return None

    body = config[len(protocol)+3:]
    
    if protocol in ('vless', 'trojan', 'hysteria2'):
        if '@' in body:
            host_part = body.split('@')[1]
            host = host_part.split(':')[0]
            try:
                ipaddress.ip_address(host)
                return host
            except ValueError:
                return None
        return None
    
    if protocol == 'vmess':
        decoded = decode_vmess_config(config)
        if decoded and 'add' in decoded:
            try:
                ipaddress.ip_address(decoded['add'])
                return decoded['add']
            except ValueError:
                pass
        return None
    
    return None

def get_country_by_ip(ip: str) -> str:
    if not ENABLE_GEOIP:
        return ''
    if ip in GEOIP_CACHE:
        return GEOIP_CACHE[ip]
    try:
        import requests
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            country = data.get('countryCode', 'XX')
            GEOIP_CACHE[ip] = country
            return country
    except Exception as e:
        logger.debug(f"Ошибка геолокации для {ip}: {e}")
    GEOIP_CACHE[ip] = 'XX'
    return 'XX'

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
    
    if protocol == 'hysteria2':
        return "HYSTERIA2"
    
    return "unknown"

def rename_config(config: str) -> str:
    protocol = None
    for p in PROTOCOL_PATTERNS:
        if config.startswith(p + "://"):
            protocol = p
            break
    if not protocol:
        return config
    
    if '#' in config:
        config = config.rsplit('#', 1)[0].rstrip()
    
    sni = extract_sni_domain(config)
    ip = extract_ip_from_config(config)
    conn_type = extract_type_from_config(config)
    
    parts = []
    if ENABLE_GEOIP and ip:
        country = get_country_by_ip(ip)
        if country and country != 'XX':
            parts.append(country)
    if sni:
        parts.append(sni)
    elif ip:
        parts.append(ip)
    else:
        parts.append("unknown")
    parts.append(conn_type)
    
    comment = "#" + " | ".join(parts)
    return config + comment

def ensure_lists_dir():
    if not os.path.exists(LISTS_DIR):
        os.makedirs(LISTS_DIR)
        logger.info(f"📁 Создана папка {LISTS_DIR}")

def load_whitelist() -> Set[str]:
    ensure_lists_dir()
    whitelist = set()
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'w', encoding='utf-8') as f:
            f.write("# Домены для LTE (приоритет 1)\n")
            f.write("example.com\n")
        logger.info(f"📝 Создан пример {WHITELIST_FILE}")
        return whitelist
    with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                whitelist.add(line)
    logger.info(f"📋 Загружено {len(whitelist)} доменов")
    return whitelist

def load_cidr_whitelist() -> List[ipaddress.ip_network]:
    ensure_lists_dir()
    cidr_list = []
    if not os.path.exists(CIDR_WHITELIST_FILE):
        with open(CIDR_WHITELIST_FILE, 'w', encoding='utf-8') as f:
            f.write("# CIDR сети для LTE (приоритет 2)\n")
            f.write("1.1.1.0/24\n")
            f.write("2.2.2.2/32\n")
            f.write("192.168.0.0/16\n")
        logger.info(f"📝 Создан пример {CIDR_WHITELIST_FILE}")
        return cidr_list
    with open(CIDR_WHITELIST_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                try:
                    cidr_list.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    logger.warning(f"⚠️ Некорректная CIDR: {line}")
    logger.info(f"📋 Загружено {len(cidr_list)} CIDR сетей")
    return cidr_list

def is_ip_in_cidr_list(ip_str: str, cidr_list: List[ipaddress.ip_network]) -> bool:
    if not ip_str or not cidr_list:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in cidr_list)
    except ValueError:
        return False

def get_config_priority(config: str, whitelist: Set[str], cidr_list: List[ipaddress.ip_network]) -> int:
    sni = extract_sni_domain(config)
    if sni and sni in whitelist:
        return 0
    ip = extract_ip_from_config(config)
    if ip and is_ip_in_cidr_list(ip, cidr_list):
        return 1
    return 2

def collect_configs_sync(contents: Dict[str, Optional[str]]) -> Set[str]:
    all_configs_set = set()
    total_raw = 0
    for url, content in contents.items():
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
                total_raw += 1
                all_configs_set.add(renamed_cfg)
    duplicates = total_raw - len(all_configs_set)
    logger.info(f"📊 Собрано уникальных конфигов: {len(all_configs_set)} (дубликатов: {duplicates})")
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
        "## 📊 Статистика\n\n"
        "| Файл | Количество |\n"
        "|------|------------|\n"
        f"| 📁 **all.txt** | `{stats['total_configs']}` |\n"
        f"| 📱 **LTE.txt** | `{stats['filtered']['lte']}` |\n"
        f"| 📶 **WiFi.txt** | `{stats['filtered']['wifi']}` |\n\n"
        "## 📡 Протоколы\n\n"
        "| Протокол | Количество |\n"
        "|----------|------------|\n"
        f"| 🔗 VLESS | `{stats['by_protocol'].get('vless', 0)}` |\n"
        f"| 📦 VMess | `{stats['by_protocol'].get('vmess', 0)}` |\n"
        f"| 🛡️ Trojan | `{stats['by_protocol'].get('trojan', 0)}` |\n"
        f"| ⚡ Hysteria2 | `{stats['by_protocol'].get('hysteria2', 0)}` |\n\n"
        "## 🗂️ Логика LTE.txt\n\n"
        "1. **Приоритет 1**: sni домен из `whitelist.txt`\n"
        "2. **Приоритет 2**: IP сервера входит в CIDR из `cidrwhitelist.txt`\n"
        "3. **WiFi.txt**: все остальные конфиги\n\n"
        "## 📋 Источники белых списков\n\n"
        "Файлы `whitelist.txt` и `cidrwhitelist.txt` взяты из репозитория:\n"
        "🔗 [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist)\n\n"
        "## 📁 Файлы\n\n"
        "- `sub/all.txt` – все конфиги\n"
        "- `sub/LTE.txt` – отфильтрованные по whitelist/CIDR и отсортированные\n"
        "- `sub/WiFi.txt` – остальные\n\n"
        "## 🔄 Автообновление\n\n"
        f"Скрипт запускается **каждый час**.\n\n---\n*LinSpisokObhod v2.4*\n"
    )
    with open(README_FILE, 'w', encoding='utf-8') as f:
        f.write(readme_content)
    logger.info("📄 README.md обновлён")

def save_configs(all_configs_set: Set[str]):
    if os.path.exists(CONFIG_DIR):
        shutil.rmtree(CONFIG_DIR)
        logger.info(f"🗑️ Папка {CONFIG_DIR} удалена (старые файлы очищены)")
    os.makedirs(CONFIG_DIR, exist_ok=True)
    logger.info(f"📁 Папка {CONFIG_DIR} создана заново")

    update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    tagged_set = {f"{cfg} {GLOBAL_TAG}" for cfg in all_configs_set}
    sorted_all = sorted(tagged_set)

    header_all = f"""#profile-title: #LSO-#LinSpisokObhod
#profile-update-interval: 1
#support-url: https://t.me/LinSpisokObhod
#announce: LinSpisokObhod подписка all.txt. Здесь находится конфиги WIFI.txt и LTE.txt Время: {update_time}
#subscription-userinfo: upload=0; download=0; total=0; expire=0

"""
    header_lte = f"""#profile-title: #LSO-#LinSpisokObhod
#profile-update-interval: 1
#support-url: https://t.me/LinSpisokObhod
#announce: LinSpisokObhod подписка LTE.txt. Здесь находится конфиги которые может подойдут для повседневного использования. Время: {update_time}
#subscription-userinfo: upload=0; download=0; total=0; expire=0

"""
    header_wifi = f"""#profile-title: #LSO-#LinSpisokObhod
#profile-update-interval: 1
#support-url: https://t.me/LinSpisokObhod
#announce: LinSpisokObhod подписка WIFI.txt. Здесь находится конфиги которые может подойдут для вайфай но может и для мобильного интернета Время: {update_time}
#subscription-userinfo: upload=0; download=0; total=0; expire=0

"""

    all_path = os.path.join(CONFIG_DIR, "all.txt")
    with open(all_path, 'w', encoding='utf-8') as f:
        f.write(header_all)
        f.write("\n".join(sorted_all) + "\n")
    logger.info(f"💾 all.txt: {len(sorted_all)}")

    whitelist = load_whitelist()
    cidr_list = load_cidr_whitelist()

    lte_set = set()
    wifi_set = set()
    for line in tagged_set:
        clean = line.replace(f" {GLOBAL_TAG}", "")
        prio = get_config_priority(clean, whitelist, cidr_list)
        if prio in (0, 1):
            lte_set.add(line)
        else:
            wifi_set.add(line)

    lte_list = sorted(lte_set, key=lambda x: get_config_priority(x.replace(f" {GLOBAL_TAG}", ""), whitelist, cidr_list))
    
    lte_path = os.path.join(CONFIG_DIR, "LTE.txt")
    with open(lte_path, 'w', encoding='utf-8') as f:
        f.write(header_lte)
        f.write("\n".join(lte_list) + "\n")
    logger.info(f"📱 LTE.txt: {len(lte_list)} (отфильтровано по whitelist/CIDR, отсортировано)")

    wifi_path = os.path.join(CONFIG_DIR, "WiFi.txt")
    with open(wifi_path, 'w', encoding='utf-8') as f:
        f.write(header_wifi)
        f.write("\n".join(sorted(wifi_set)) + "\n")
    logger.info(f"📶 WiFi.txt: {len(wifi_set)}")

    protocol_stats = {proto: 0 for proto in PROTOCOL_PATTERNS}
    for cfg in all_configs_set:
        proto = get_protocol_from_config(cfg)
        if proto in protocol_stats:
            protocol_stats[proto] += 1

    stats = {
        "timestamp": datetime.now().isoformat(),
        "total_configs": len(tagged_set),
        "by_protocol": protocol_stats,
        "filtered": {"lte": len(lte_list), "wifi": len(wifi_set)}
    }
    stats_path = os.path.join(CONFIG_DIR, "stats.json")
    with open(stats_path, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    logger.info("📊 Статистика сохранена")

    update_readme(stats, len(SOURCES))
    return stats

async def main_async():
    start_time = time.time()
    print("=" * 60)
    print("🚀 LinSpisokObhod v2.4 (асинхронный сбор, геолокация включена)")
    print("=" * 60)
    print(f"📋 Источников: {len(SOURCES)}")
    print(f"🔄 Протоколы: {', '.join(PROTOCOL_PATTERNS.keys())}")
    print(f"📄 Whitelist: {WHITELIST_FILE}")
    print(f"🗂️ CIDR whitelist: {CIDR_WHITELIST_FILE}")
    print(f"📁 Результаты в папке: {CONFIG_DIR}")
    print("🌍 Геолокация: ВКЛЮЧЕНА (ip-api.com)")
    print("=" * 60)

    contents = await fetch_all_sources()
    all_configs = collect_configs_sync(contents)
    stats = save_configs(all_configs)

    elapsed = time.time() - start_time
    print("\n" + "=" * 60)
    print("📊 ИТОГИ СБОРА:")
    print("=" * 60)
    print(f"📈 Всего уникальных: {stats['total_configs']}")
    print(f"   📱 LTE: {stats['filtered']['lte']}")
    print(f"   📶 WiFi: {stats['filtered']['wifi']}")
    for proto, count in stats['by_protocol'].items():
        if count:
            print(f"   {proto.upper()}: {count}")
    print(f"⏱️ Время: {elapsed:.2f} секунд")
    print("=" * 60)

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("⏹️ Прерывание")
    except Exception as e:
        logger.error(f"❌ Ошибка: {e}")
        raise
