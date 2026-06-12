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
import base64
from datetime import datetime
from urllib.parse import parse_qs
from typing import Dict, Set, Optional, List

# ========== НАСТРОЙКИ ==========
ENABLE_GEOIP = True
GEOIP_PARALLEL = 10
GEOIP_DELAY = 0.1
IPINFO_TOKENS = [
    os.environ.get("IPINFO_TOKEN"),
    "a94d8c011ca891"
]
IPINFO_TOKENS = [t for t in IPINFO_TOKENS if t]
if ENABLE_GEOIP and not IPINFO_TOKENS:
    raise ValueError("No IPINFO_TOKEN provided. Please add at least one token.")

GEOIP_CACHE = {}
GEOIP_SEMAPHORE = asyncio.Semaphore(GEOIP_PARALLEL)
TOKEN_INDEX = 0
TOKEN_LOCK = asyncio.Lock()

SOURCES = [
    "https://raw.githubusercontent.com/tahmaseb73/Telegram_config_collector/refs/heads/main/configs/proxy_configs.txt",
    "https://gitverse.ru/RoGo/mobile-whitelist/content/master/mobile-whitelist-1.txt",
    "https://raw.githubusercontent.com/v0id9/vpn-configs/refs/heads/main/vpn.txt",
    "https://tinyurl.com/SemqkaVLESS",
    "https://mifa.world/vless",
    "https://mifa.world/hysteria",
    "https://mifa.world/vmess",
    "https://mifa.world/trojan",
    "https://mifa.world/ss",
    "https://gist.github.com/DestroyST6767/50af50221ca1858ba2084efc0f524fbc.txt"
]

REQUEST_TIMEOUT = 15
CONFIG_DIR = "sub"
LISTS_DIR = "lists"
WHITELIST_FILE = os.path.join(LISTS_DIR, "whitelist.txt")
CIDR_WHITELIST_FILE = os.path.join(LISTS_DIR, "cidrwhitelist.txt")
GLOBAL_TAG = "[#LSO - #LinSpisokObhod]"

PROTOCOL_PATTERNS = {
    'vless': re.compile(r'vless://[A-Za-z0-9+/=@:;,\?&%#\.\-_~!$*()]+', re.IGNORECASE),
    'vmess': re.compile(r'vmess://[A-Za-z0-9+/=]+', re.IGNORECASE),
    'trojan': re.compile(r'trojan://[A-Za-z0-9+/=@:;,\?&%#\.\-_~!$*()]+', re.IGNORECASE),
    'hysteria2': re.compile(r'hysteria2://[A-Za-z0-9+/=@:;,\?&%#\.\-_~!$*()]+', re.IGNORECASE),
}

# Настройка логирования: только вывод в консоль, без файла
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# === АСИНХРОННАЯ ЗАГРУЗКА ===
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

# === ПАРСИНГ КОНФИГОВ ===
def extract_configs_from_text(text: str, source_url: str) -> Dict[str, Set[str]]:
    configs = {proto: set() for proto in PROTOCOL_PATTERNS}
    for protocol, pattern in PROTOCOL_PATTERNS.items():
        matches = pattern.findall(text)
        for match in matches:
            if 50 < len(match) < 5000:
                configs[protocol].add(match)
    return configs

def extract_ip_from_config(config: str) -> Optional[str]:
    protocol = None
    for p in PROTOCOL_PATTERNS:
        if config.startswith(p + "://"):
            protocol = p
            break
    if not protocol:
        return None
    body = config[len(protocol)+3:]
    if '@' in body:
        host_part = body.split('@')[1]
        host = host_part.split(':')[0]
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            return None
    return None

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
        return True
    elif protocol == 'trojan':
        sni = extract_sni_domain(config)
        ip = extract_ip_from_config(config)
        if not (sni or ip):
            return False
        return True
    elif protocol == 'hysteria2':
        ip = extract_ip_from_config(config)
        sni = extract_sni_domain(config)
        if not (ip or sni):
            return False
        return True
    return True

# === ГЕОЛОКАЦИЯ (IPinfo с ротацией токенов) ===
async def get_next_token():
    global TOKEN_INDEX
    async with TOKEN_LOCK:
        token = IPINFO_TOKENS[TOKEN_INDEX % len(IPINFO_TOKENS)]
        TOKEN_INDEX += 1
        return token

async def resolve_country(ip: str, session: aiohttp.ClientSession) -> str:
    async with GEOIP_SEMAPHORE:
        if ip in GEOIP_CACHE:
            return GEOIP_CACHE[ip]
        country = 'XX'
        token = await get_next_token()
        try:
            url = f"https://api.ipinfo.io/lite/{ip}/country?token={token}"
            async with session.get(url, timeout=5) as resp:
                if resp.status == 200:
                    country = (await resp.text()).strip()
                    if not country:
                        country = 'XX'
                    if len(GEOIP_CACHE) < 5 and country != 'XX':
                        logger.info(f"✅ IPinfo (token {token[:4]}...): {ip} -> {country}")
                elif resp.status == 429:
                    logger.warning(f"⚠️ Токен {token[:4]}... лимит, переключаюсь")
                    return await resolve_country(ip, session)
                else:
                    logger.debug(f"⚠️ IPinfo ошибка {resp.status} для {ip}")
        except Exception as e:
            logger.debug(f"Ошибка IPinfo для {ip}: {e}")
        GEOIP_CACHE[ip] = country
        return country

async def resolve_countries_parallel(ips: List[str]) -> Dict[str, str]:
    if not ips:
        return {}
    unique_ips = [ip for ip in set(ips) if ip not in GEOIP_CACHE]
    if not unique_ips:
        return GEOIP_CACHE.copy()
    total = len(unique_ips)
    logger.info(f"🌍 Определяю страны для {total} уникальных IP через IPinfo (параллельно {GEOIP_PARALLEL})")
    processed = 0
    async with aiohttp.ClientSession() as session:
        tasks = [resolve_country(ip, session) for ip in unique_ips]
        for future in asyncio.as_completed(tasks):
            await future
            processed += 1
            if processed % 100 == 0 or processed == total:
                logger.info(f"   Прогресс геолокации: {processed}/{total} IP обработано")
            await asyncio.sleep(GEOIP_DELAY)
    logger.info("✅ Геолокация завершена")
    return GEOIP_CACHE.copy()

# === ФУНКЦИЯ ПЕРЕИМЕНОВАНИЯ (ДОБАВЛЯЕТ СТРАНУ В КОММЕНТАРИЙ) ===
def rename_config(config: str, country: str = '') -> str:
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
    conn_type = "unknown"
    body = config[len(protocol)+3:]
    if '?' in body:
        query_part = body.split('?', 1)[1]
        params = parse_qs(query_part)
        if 'type' in params:
            t = params['type'][0].lower()
            if t == 'ws':
                conn_type = "WebSocket"
            else:
                conn_type = t.upper()
    if protocol == 'hysteria2':
        conn_type = "HYSTERIA2"
    parts = []
    if ip and country and country != 'XX':
        parts.append(country)
    else:
        parts.append("unknown")
    if sni:
        parts.append(sni)
    elif ip:
        parts.append(ip)
    else:
        parts.append("unknown")
    parts.append(conn_type)
    comment = "#" + " | ".join(parts)
    return config + comment

# === ЗАГРУЗКА БЕЛЫХ СПИСКОВ ===
def ensure_lists_dir():
    if not os.path.exists(LISTS_DIR):
        os.makedirs(LISTS_DIR)

def load_whitelist() -> Set[str]:
    ensure_lists_dir()
    whitelist = set()
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'w', encoding='utf-8') as f:
            f.write("# Домены для LTE (приоритет 1)\n")
            f.write("# Поддерживаются субдомены и зона .yandex\n")
            f.write("example.com\n")
            f.write(".yandex\n")
        logger.info(f"📝 Создан пример {WHITELIST_FILE}")
        return whitelist
    with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                whitelist.add(line)
    logger.info(f"📋 Загружено {len(whitelist)} доменов/зон")
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

def is_domain_allowed(domain: str, whitelist: Set[str]) -> bool:
    if not domain:
        return False
    domain = domain.lower()
    for allowed in whitelist:
        allowed_lower = allowed.lower()
        if allowed_lower.startswith('.'):
            if domain.endswith(allowed_lower):
                return True
        else:
            if domain == allowed_lower or domain.endswith('.' + allowed_lower):
                return True
    return False

def get_config_priority(config: str, whitelist: Set[str], cidr_list: List[ipaddress.ip_network]) -> int:
    sni = extract_sni_domain(config)
    if sni and is_domain_allowed(sni, whitelist):
        return 0
    ip = extract_ip_from_config(config)
    if ip and is_ip_in_cidr_list(ip, cidr_list):
        return 1
    return 2

# === ОСНОВНОЙ СБОР С ГЕОЛОКАЦИЕЙ ===
async def collect_configs_async(contents: Dict[str, Optional[str]]) -> Set[str]:
    raw_configs = []
    all_ips = set()
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
                raw_configs.append(cfg)
                ip = extract_ip_from_config(cfg)
                if ip:
                    all_ips.add(ip)
    total_raw = len(raw_configs)
    logger.info(f"🔄 Всего валидных конфигов (до переименования): {total_raw}")

    if ENABLE_GEOIP and all_ips:
        await resolve_countries_parallel(list(all_ips))
    elif ENABLE_GEOIP:
        logger.info("🌍 Геолокация включена, но IP для определения не найдены")

    renamed_configs = []
    for i, cfg in enumerate(raw_configs, 1):
        ip = extract_ip_from_config(cfg)
        country = GEOIP_CACHE.get(ip, '') if ip and ENABLE_GEOIP else ''
        renamed_cfg = rename_config(cfg, country)
        renamed_configs.append(renamed_cfg)
        if i % 500 == 0 or i == total_raw:
            logger.info(f"⏳ Прогресс переименования: {i}/{total_raw} конфигов")

    all_configs_set = set(renamed_configs)
    duplicates = total_raw - len(all_configs_set)
    logger.info(f"📊 Собрано уникальных конфигов: {len(all_configs_set)} (дубликатов: {duplicates})")
    return all_configs_set

# === СОХРАНЕНИЕ И ФИЛЬТРАЦИЯ ===
def save_base64_encoded(original_path: str, encoded_path: str):
    if os.path.exists(original_path):
        with open(original_path, 'rb') as f:
            data = f.read()
        b64_data = base64.b64encode(data).decode('ascii')
        with open(encoded_path, 'w', encoding='ascii') as f:
            f.write(b64_data)
        logger.info(f"🔐 Base64 сохранён: {encoded_path}")

def save_configs(all_configs_set: Set[str]):
    if os.path.exists(CONFIG_DIR):
        shutil.rmtree(CONFIG_DIR)
        logger.info(f"🗑️ Папка {CONFIG_DIR} удалена (старые файлы очищены)")
    os.makedirs(CONFIG_DIR, exist_ok=True)
    logger.info(f"📁 Папка {CONFIG_DIR} создана заново")

    update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    tagged_set = {f"{cfg} {GLOBAL_TAG}" for cfg in all_configs_set}
    
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
    all_path = os.path.join(CONFIG_DIR, "ALL.txt")
    with open(all_path, 'w', encoding='utf-8') as f:
        f.write(header_all)
        f.write("\n".join(sorted(tagged_set)) + "\n")
    logger.info(f"💾 ALL.txt: {len(tagged_set)}")

    whitelist = load_whitelist()
    cidr_list = load_cidr_whitelist()

    lte_set = set()
    wifi_set = set()
    for line in tagged_set:
        clean = line.replace(f" {GLOBAL_TAG}", "")
        if get_config_priority(clean, whitelist, cidr_list) in (0, 1):
            lte_set.add(line)
        else:
            wifi_set.add(line)

    lte_list = sorted(lte_set, key=lambda x: get_config_priority(x.replace(f" {GLOBAL_TAG}", ""), whitelist, cidr_list))
    wifi_list = sorted(wifi_set)
    
    lte_path = os.path.join(CONFIG_DIR, "LTE.txt")
    with open(lte_path, 'w', encoding='utf-8') as f:
        f.write(header_lte)
        f.write("\n".join(lte_list) + "\n")
    logger.info(f"📱 LTE.txt: {len(lte_list)} (отфильтровано)")

    wifi_path = os.path.join(CONFIG_DIR, "WiFi.txt")
    with open(wifi_path, 'w', encoding='utf-8') as f:
        f.write(header_wifi)
        f.write("\n".join(wifi_list) + "\n")
    logger.info(f"📶 WiFi.txt: {len(wifi_list)}")

    # Base64
    save_base64_encoded(all_path, os.path.join(CONFIG_DIR, "ALL.64.txt"))
    save_base64_encoded(lte_path, os.path.join(CONFIG_DIR, "LTE.64.txt"))
    save_base64_encoded(wifi_path, os.path.join(CONFIG_DIR, "WIFI.64.txt"))

    # Статистика НЕ СОЗДАЁТСЯ
    logger.info("✅ Готово. Файлы stats.json и collector.log не создавались.")

# === ЗАПУСК ===
async def main_async():
    start_time = time.time()
    print("=" * 60)
    print("🚀 LinSpisokObhod (геолокация, поддержка субдоменов и .yandex, base64)")
    print("=" * 60)
    print(f"📋 Источников: {len(SOURCES)}")
    print(f"📁 Результаты в папке: {CONFIG_DIR}")
    if ENABLE_GEOIP:
        print(f"🌍 Геолокация: ВКЛЮЧЕНА (IPinfo, токенов: {len(IPINFO_TOKENS)})")
    else:
        print("🌍 Геолокация: ВЫКЛЮЧЕНА")
    print("=" * 60)

    contents = await fetch_all_sources()
    all_configs = await collect_configs_async(contents)
    save_configs(all_configs)

    elapsed = time.time() - start_time
    print("\n" + "=" * 60)
    print("📊 ИТОГИ СБОРА:")
    print("=" * 60)
    print(f"📈 Всего уникальных: {len(all_configs)}")
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
