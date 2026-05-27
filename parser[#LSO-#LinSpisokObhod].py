#!/usr/bin/env python3
"""
Сборщик и полноценная проверка прокси конфигураций (VLESS/VMess/Trojan/SS/Hysteria2).
Использует нативные ядра Xray-core и Hysteria2.
Поддерживает hysteria2:// и hy2://.
"""

import os
import re
import sys
import json
import base64
import asyncio
import subprocess
import tempfile
import shutil
import platform
import urllib.request
import zipfile
import tarfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

import aiohttp
import aiofiles

# ================== НАСТРОЙКИ ==================
SOURCES: List[str] = [
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/1.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/2.txt",
    "https://raw.githubusercontent.com/tahmaseb73/Telegram_config_collector/refs/heads/main/configs/proxy_configs.txt",
    "https://gitverse.ru/RoGo/mobile-whitelist/content/master/mobile-whitelist-1.txt",
    "https://raw.githubusercontent.com/v0id9/vpn-configs/refs/heads/main/vpn.txt",
    "https://tinyurl.com/SemqkaVLESS",
]

OUTPUT_DIR: str = "sub"
TIMEOUT: int = 8
MAX_WORKERS: int = 5
TEST_URL: str = "https://www.google.com/generate_204"
USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==================
def detect_protocol(line: str) -> Optional[str]:
    line = line.strip()
    if not line:
        return None
    if line.startswith("vless://"):
        return "vless"
    if line.startswith("trojan://"):
        return "trojan"
    if line.startswith("hysteria2://") or line.startswith("hy2://"):
        return "hy2"
    if line.startswith("vmess://"):
        return "vmess"
    if line.startswith("ss://"):
        return "ss"
    if '|' in line and re.search(r'\d+\.\d+\.\d+\.\d+:\d+', line):
        return "simple_trojan_or_hy2"
    return None

def parse_config(raw: str, proto: str) -> Dict[str, Any]:
    base_cfg: Dict[str, Any] = {"raw": raw, "type": proto}
    if proto == "vmess" and raw.startswith("vmess://"):
        try:
            b64_str = raw[8:]
            missing_padding = len(b64_str) % 4
            if missing_padding:
                b64_str += "=" * (4 - missing_padding)
            decoded = base64.b64decode(b64_str).decode("utf-8")
            data = json.loads(decoded)
            base_cfg["host"] = data.get("add", "")
            base_cfg["port"] = int(data.get("port", 0))
            base_cfg["uuid"] = data.get("id", "")
            base_cfg["aid"] = data.get("aid", "0")
            base_cfg["security"] = data.get("scy", "auto")
            net = data.get("net", "tcp")
            base_cfg["net"] = net
            if net == "ws":
                base_cfg["path"] = data.get("path", "/")
                base_cfg["host_header"] = data.get("host", "")
        except Exception:
            pass
    elif proto == "vless" and raw.startswith("vless://"):
        parts = raw[8:].split("@")
        if len(parts) == 2:
            base_cfg["uuid"] = parts[0]
            host_port_part = parts[1].split("?")[0].split("#")[0]
            if ":" in host_port_part:
                base_cfg["host"], base_cfg["port"] = host_port_part.split(":")
                base_cfg["port"] = int(base_cfg["port"])
            else:
                base_cfg["host"], base_cfg["port"] = host_port_part, 443
            query_part = raw.split("?")[1] if "?" in raw else ""
            if "encryption=" in query_part:
                base_cfg["encryption"] = "none"
            if "security=" in query_part:
                base_cfg["security"] = query_part.split("security=")[1].split("&")[0]
            if "type=" in query_part:
                base_cfg["net"] = query_part.split("type=")[1].split("&")[0]
    elif proto == "trojan" and raw.startswith("trojan://"):
        parts = raw[9:].split("@")
        if len(parts) == 2:
            base_cfg["password"] = parts[0]
            host_port_part = parts[1].split("?")[0].split("#")[0]
            if ":" in host_port_part:
                base_cfg["host"], base_cfg["port"] = host_port_part.split(":")
                base_cfg["port"] = int(base_cfg["port"])
            else:
                base_cfg["host"], base_cfg["port"] = host_port_part, 443
            if "sni=" in raw:
                base_cfg["sni"] = raw.split("sni=")[1].split("&")[0]
    elif proto == "hy2" and (raw.startswith("hysteria2://") or raw.startswith("hy2://")):
        clean = raw.replace("hysteria2://", "").replace("hy2://", "")
        match = re.search(r'([^:/?#]+):?(\d*)', clean)
        if match:
            base_cfg["host"] = match.group(1)
            base_cfg["port"] = int(match.group(2)) if match.group(2) else 443
        auth_match = re.search(r'auth=([^&]+)', raw)
        if auth_match:
            base_cfg["auth"] = auth_match.group(1)
        sni_match = re.search(r'sni=([^&]+)', raw)
        if sni_match:
            base_cfg["sni"] = sni_match.group(1)
    elif proto == "ss" and raw.startswith("ss://"):
        if ":@" in raw:
            main_part = raw[5:].split("@")
            if len(main_part) == 2:
                method_pass = main_part[0]
                host_port_part = main_part[1].split("#")[0]
                base_cfg["method"] = method_pass.split(":")[0] if ":" in method_pass else ""
                base_cfg["password"] = method_pass.split(":")[1] if ":" in method_pass else ""
                if ":" in host_port_part:
                    base_cfg["host"], base_cfg["port"] = host_port_part.split(":")
                    base_cfg["port"] = int(base_cfg["port"])
                else:
                    base_cfg["host"], base_cfg["port"] = host_port_part, 443
    elif "simple_trojan_or_hy2" in proto and '|' in raw:
        parts = raw.split('|')
        host_port = parts[0].split(':')
        base_cfg["type"] = "trojan"
        base_cfg["host"] = host_port[0]
        base_cfg["port"] = int(host_port[1]) if len(host_port) > 1 else 443
        base_cfg["password"] = parts[1] if len(parts) > 1 else ""
    else:
        base_cfg["type"] = None
    return base_cfg

# ================== ЗАГРУЗКА БИНАРНИКОВ ==================
def ensure_binaries():
    vendor_dir = Path("vendor")
    vendor_dir.mkdir(parents=True, exist_ok=True)
    
    sys_os = platform.system().lower()
    arch = platform.machine().lower()
    if "x86_64" in arch or "amd64" in arch:
        arch_str = "64"
    elif "aarch64" in arch or "arm64" in arch:
        arch_str = "arm64"
    else:
        arch_str = "64"

    # Xray-core
    xray_dir = vendor_dir / "xray"
    xray_dir.mkdir(exist_ok=True)
    if sys_os == "linux":
        xray_bin = xray_dir / "xray"
        xray_url = f"https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-{arch_str}.zip"
    elif sys_os == "darwin":
        xray_bin = xray_dir / "xray"
        xray_url = f"https://github.com/XTLS/Xray-core/releases/latest/download/Xray-macos-{arch_str}.zip"
    elif sys_os == "windows":
        xray_bin = xray_dir / "xray.exe"
        xray_url = f"https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-{arch_str}.zip"
    else:
        xray_bin = None
    
    if xray_bin and not xray_bin.exists():
        print("📦 Загрузка Xray-core...")
        zip_path = xray_dir / "xray.zip"
        urllib.request.urlretrieve(xray_url, zip_path)
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(xray_dir)
        zip_path.unlink()
        if sys_os != "windows":
            os.chmod(xray_bin, 0o755)
        print("✅ Xray-core готов")
    
    # Hysteria2
    hy2_dir = vendor_dir / "hysteria2"
    hy2_dir.mkdir(exist_ok=True)
    if sys_os == "linux":
        hy2_bin = hy2_dir / "hysteria2"
        hy2_url = f"https://github.com/apernet/hysteria/releases/latest/download/hysteria2-linux-{arch_str}.tar.gz"
    elif sys_os == "darwin":
        hy2_bin = hy2_dir / "hysteria2"
        hy2_url = f"https://github.com/apernet/hysteria/releases/latest/download/hysteria2-darwin-{arch_str}.tar.gz"
    elif sys_os == "windows":
        hy2_bin = hy2_dir / "hysteria2.exe"
        hy2_url = f"https://github.com/apernet/hysteria/releases/latest/download/hysteria2-windows-{arch_str}.tar.gz"
    else:
        hy2_bin = None
    
    if hy2_bin and not hy2_bin.exists():
        print("📦 Загрузка Hysteria2...")
        tar_path = hy2_dir / "hysteria2.tar.gz"
        urllib.request.urlretrieve(hy2_url, tar_path)
        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extractall(hy2_dir)
        tar_path.unlink()
        if sys_os != "windows":
            os.chmod(hy2_bin, 0o755)
        print("✅ Hysteria2 готов")
    
    return xray_bin, hy2_bin

# ================== ПРОВЕРКА ЧЕРЕЗ ЯДРА ==================
async def run_xray(config: Dict) -> Tuple[bool, float]:
    xray_bin, _ = ensure_binaries()
    if not xray_bin or not xray_bin.exists():
        return False, 0
    
    tmp_dir = tempfile.mkdtemp()
    config_path = Path(tmp_dir) / "config.json"
    
    outbound = {
        "protocol": config["type"],
        "settings": {},
        "streamSettings": {}
    }
    
    if config["type"] == "vmess":
        outbound["settings"]["vnext"] = [{
            "address": config.get("host"),
            "port": config.get("port"),
            "users": [{"id": config.get("uuid"), "alterId": int(config.get("aid", 0)), "security": config.get("security", "auto")}]
        }]
        net = config.get("net", "tcp")
        outbound["streamSettings"]["network"] = net
        if net == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": config.get("path", "/"),
                "headers": {"Host": config.get("host_header", "")}
            }
        if config.get("security") == "reality":
            outbound["streamSettings"]["security"] = "reality"
            outbound["streamSettings"]["realitySettings"] = {
                "serverName": config.get("sni", ""),
                "fingerprint": "chrome",
                "publicKey": config.get("pbk", ""),
                "shortId": config.get("sid", "")
            }
        else:
            outbound["streamSettings"]["security"] = config.get("security", "none")
            if config.get("security") not in [None, "none"]:
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": config.get("sni", config.get("host"))
                }
    elif config["type"] == "vless":
        outbound["settings"]["vnext"] = [{
            "address": config.get("host"),
            "port": config.get("port"),
            "users": [{"id": config.get("uuid"), "encryption": config.get("encryption", "none"), "flow": config.get("flow", "")}]
        }]
        net = config.get("net", "tcp")
        outbound["streamSettings"]["network"] = net
        if net == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": config.get("path", "/"),
                "headers": {"Host": config.get("host", "")}
            }
        if config.get("security") == "reality":
            outbound["streamSettings"]["security"] = "reality"
            outbound["streamSettings"]["realitySettings"] = {
                "serverName": config.get("sni", ""),
                "fingerprint": "chrome",
                "publicKey": config.get("pbk", ""),
                "shortId": config.get("sid", "")
            }
        else:
            outbound["streamSettings"]["security"] = config.get("security", "none")
            if config.get("security") not in [None, "none"]:
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": config.get("sni", config.get("host"))
                }
    elif config["type"] == "trojan":
        outbound["settings"]["servers"] = [{
            "address": config.get("host"),
            "port": config.get("port"),
            "password": config.get("password"),
            "flow": config.get("flow", "")
        }]
        outbound["streamSettings"]["network"] = "tcp"
        outbound["streamSettings"]["security"] = "tls"
        outbound["streamSettings"]["tlsSettings"] = {
            "serverName": config.get("sni", config.get("host"))
        }
    elif config["type"] == "ss":
        outbound["settings"]["servers"] = [{
            "address": config.get("host"),
            "port": config.get("port"),
            "method": config.get("method"),
            "password": config.get("password"),
            "level": 1
        }]
        outbound["streamSettings"]["network"] = "tcp"
        outbound["streamSettings"]["security"] = "none"
    else:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return False, 0
    
    full_config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": 44320,
            "protocol": "http",
            "settings": {"auth": "noauth"}
        }],
        "outbounds": [outbound]
    }
    with open(config_path, "w") as f:
        json.dump(full_config, f)
    
    start_time = asyncio.get_event_loop().time()
    try:
        process = await asyncio.create_subprocess_exec(
            str(xray_bin), "-c", str(config_path),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        await asyncio.sleep(1.5)
        async with aiohttp.ClientSession() as session:
            proxy = f"http://127.0.0.1:44320"
            try:
                async with session.get(TEST_URL, proxy=proxy, timeout=TIMEOUT) as resp:
                    if resp.status in [200, 204]:
                        latency = (asyncio.get_event_loop().time() - start_time) * 1000
                        process.terminate()
                        await process.wait()
                        shutil.rmtree(tmp_dir, ignore_errors=True)
                        return True, latency
                    else:
                        process.terminate()
                        await process.wait()
                        shutil.rmtree(tmp_dir, ignore_errors=True)
                        return False, 0
            except Exception:
                process.terminate()
                await process.wait()
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return False, 0
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return False, 0

async def run_hysteria2(config: Dict) -> Tuple[bool, float]:
    _, hy2_bin = ensure_binaries()
    if not hy2_bin or not hy2_bin.exists():
        return False, 0
    
    tmp_dir = tempfile.mkdtemp()
    config_path = Path(tmp_dir) / "config.json"
    hy2_config = {
        "server": f"{config.get('host')}:{config.get('port')}",
        "auth": config.get("auth", ""),
        "tls": {"sni": config.get("sni", config.get("host")), "insecure": True},
        "socks5": {"listen": "127.0.0.1:44321"},
        "http": {"listen": "127.0.0.1:44322"}
    }
    with open(config_path, "w") as f:
        json.dump(hy2_config, f)
    
    start_time = asyncio.get_event_loop().time()
    try:
        process = await asyncio.create_subprocess_exec(
            str(hy2_bin), "client", "-c", str(config_path),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        await asyncio.sleep(2)
        async with aiohttp.ClientSession() as session:
            proxy = "http://127.0.0.1:44322"
            try:
                async with session.get(TEST_URL, proxy=proxy, timeout=TIMEOUT) as resp:
                    if resp.status in [200, 204]:
                        latency = (asyncio.get_event_loop().time() - start_time) * 1000
                        process.terminate()
                        await process.wait()
                        shutil.rmtree(tmp_dir, ignore_errors=True)
                        return True, latency
                    else:
                        process.terminate()
                        await process.wait()
                        shutil.rmtree(tmp_dir, ignore_errors=True)
                        return False, 0
            except Exception:
                process.terminate()
                await process.wait()
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return False, 0
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return False, 0

async def validate_config(config: Dict) -> Optional[Dict]:
    proto = config.get("type")
    if proto in ["vmess", "vless", "trojan", "ss"]:
        ok, ping = await run_xray(config)
    elif proto == "hy2":
        ok, ping = await run_hysteria2(config)
    else:
        return None
    if ok:
        config["ping"] = round(ping, 2)
        return config
    return None

# ================== ОСНОВНОЙ КЛАСС СБОРЩИКА ==================
class MultiProtocolCollector:
    def __init__(self):
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        self.raw_by_proto: Dict[str, List[Dict]] = {p: [] for p in ["vless", "trojan", "hy2", "vmess", "ss"]}
        self.valid_by_proto: Dict[str, List[Dict]] = {p: [] for p in ["vless", "trojan", "hy2", "vmess", "ss"]}

    async def fetch_and_save_raw(self, session: aiohttp.ClientSession, url: str, idx: int) -> str:
        try:
            async with session.get(url, timeout=15) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    filename = os.path.join(OUTPUT_DIR, f"raw_{idx+1}.txt")
                    async with aiofiles.open(filename, "w", encoding="utf-8") as f:
                        await f.write(text)
                    print(f"💾 Сохранён {filename}")
                    return text
        except Exception as e:
            print(f"⚠️ Ошибка {url}: {e}")
        return ""

    async def load_all_configs(self) -> List[str]:
        all_lines = []
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_and_save_raw(session, url, i) for i, url in enumerate(SOURCES)]
            results = await asyncio.gather(*tasks)
            for text in results:
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    all_lines.append(line)
        return all_lines

    def sort_by_protocol(self, lines: List[str]):
        for line in lines:
            proto = detect_protocol(line)
            if proto:
                cfg = parse_config(line, proto)
                if cfg.get("type") and cfg["type"] in self.raw_by_proto:
                    self.raw_by_proto[cfg["type"]].append(cfg)
        # Сохраняем непроверенные
        all_path = os.path.join(OUTPUT_DIR, "all.txt")
        with open(all_path, "w", encoding="utf-8") as f:
            for proto, items in self.raw_by_proto.items():
                for item in items:
                    if "raw" in item:
                        f.write(item["raw"] + "\n")
        for proto, items in self.raw_by_proto.items():
            path = os.path.join(OUTPUT_DIR, f"{proto}.txt")
            with open(path, "w", encoding="utf-8") as f:
                for item in items:
                    if "raw" in item:
                        f.write(item["raw"] + "\n")
        print("📁 Непроверенные конфиги разложены по файлам.")

    async def validate_all(self):
        sem = asyncio.Semaphore(MAX_WORKERS)
        async def check_one(cfg):
            async with sem:
                return await validate_config(cfg)
        for proto in list(self.raw_by_proto.keys()):
            if not self.raw_by_proto[proto]:
                print(f"⚠️ {proto.upper()}: нет конфигов для проверки")
                continue
            tasks = [check_one(cfg) for cfg in self.raw_by_proto[proto]]
            results = await asyncio.gather(*tasks)
            self.valid_by_proto[proto] = [r for r in results if r]
            print(f"✅ {proto.upper()}: {len(self.valid_by_proto[proto])}/{len(self.raw_by_proto[proto])} рабочих")
        # Сохраняем валидные
        all_valid_path = os.path.join(OUTPUT_DIR, "all.valid.txt")
        with open(all_valid_path, "w", encoding="utf-8") as f:
            for proto, items in self.valid_by_proto.items():
                for item in items:
                    if "raw" in item:
                        f.write(item["raw"] + "\n")
        for proto, items in self.valid_by_proto.items():
            path = os.path.join(OUTPUT_DIR, f"{proto}.valid.txt")
            with open(path, "w", encoding="utf-8") as f:
                for item in items:
                    if "raw" in item:
                        f.write(item["raw"] + "\n")
        print("💾 Валидные конфиги сохранены.")

    async def run(self):
        print("🔄 Загрузка источников в папку sub...")
        lines = await self.load_all_configs()
        print(f"📥 Всего строк: {len(lines)}")
        print("🏷️ Сортировка по протоколам...")
        self.sort_by_protocol(lines)
        print("⚡ Запуск полноценной проверки через ядра Xray и Hysteria2...")
        await self.validate_all()
        print("🎉 Готово!")

async def main():
    collector = MultiProtocolCollector()
    await collector.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
