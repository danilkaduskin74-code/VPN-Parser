import subprocess
import os
import json
import base64
import re
import tempfile
import socket
import time
import random
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

XRAY_BINARY = './xray'
TEST_URL = 'http://connectivitycheck.gstatic.com/generate_204'
TIMEOUT = 8
MAX_CHECK = 800

def parse_host_port(key):
    try:
        if key.startswith('vmess://'):
            data = key[8:]
            padded = data + '=' * (4 - len(data) % 4)
            config = json.loads(base64.b64decode(padded).decode('utf-8'))
            return config.get('add'), int(config.get('port', 0))
        match = re.search(r'@([^:@\[\]]+):(\d+)', key)
        if match:
            return match.group(1), int(match.group(2))
    except:
        pass
    return None, None

def get_free_port():
    with socket.socket() as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def build_config(key, socks_port):
    outbound = None
    try:
        if key.startswith('vless://'):
            match = re.match(r'vless://([^@]+)@([^:]+):(\d+)\??([^#]*)', key)
            if not match:
                return None
            uuid, host, port, params = match.groups()
            param_dict = {}
            for p in params.split('&'):
                if '=' in p:
                    k, v = p.split('=', 1)
                    param_dict[k] = v

            stream = {"network": param_dict.get("type", "tcp")}
            security = param_dict.get("security", "none")
            stream["security"] = security

            if security == "reality":
                stream["realitySettings"] = {
                    "fingerprint": param_dict.get("fp", "chrome"),
                    "serverName": param_dict.get("sni", host),
                    "publicKey": param_dict.get("pbk", ""),
                    "shortId": param_dict.get("sid", ""),
                    "spiderX": param_dict.get("spx", "/")
                }
            elif security == "tls":
                stream["tlsSettings"] = {
                    "serverName": param_dict.get("sni", host),
                    "allowInsecure": True
                }

            outbound = {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": int(port),
                        "users": [{"id": uuid, "encryption": "none", "flow": param_dict.get("flow", "")}]
                    }]
                },
                "streamSettings": stream
            }

        elif key.startswith('trojan://'):
            match = re.match(r'trojan://([^@]+)@([^:]+):(\d+)\??([^#]*)', key)
            if not match:
                return None
            password, host, port, params = match.groups()
            param_dict = {}
            for p in params.split('&'):
                if '=' in p:
                    k, v = p.split('=', 1)
                    param_dict[k] = v

            outbound = {
                "tag": "proxy",
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": int(port),
                        "password": password
                    }]
                },
                "streamSettings": {
                    "network": param_dict.get("type", "tcp"),
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": param_dict.get("sni", host),
                        "allowInsecure": True
                    }
                }
            }

        elif key.startswith('vmess://'):
            data = key[8:]
            padded = data + '=' * (4 - len(data) % 4)
            c = json.loads(base64.b64decode(padded).decode('utf-8'))
            stream = {"network": c.get("net", "tcp")}
            if c.get("tls") == "tls":
                stream["security"] = "tls"
                stream["tlsSettings"] = {"allowInsecure": True}
            outbound = {
"tag": "proxy",
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": c.get("add", ""),
                        "port": int(c.get("port", 0)),
                        "users": [{
                            "id": c.get("id", ""),
                            "alterId": int(c.get("aid", 0)),
                            "security": c.get("scy", "auto")
                        }]
                    }]
                },
                "streamSettings": stream
            }

    except Exception as e:
        return None

    if not outbound:
        return None

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "socks-in",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": False}
        }],
        "outbounds": [
            outbound,
            {"tag": "direct", "protocol": "freedom"}
        ],
        "routing": {
            "rules": [{
                "type": "field",
                "inboundTag": ["socks-in"],
                "outboundTag": "proxy"
            }]
        }
    }

def check_key(key):
    socks_port = get_free_port()
    config = build_config(key, socks_port)
    if not config:
        return key, False

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f)
        config_path = f.name

    proc = None
    try:
        proc = subprocess.Popen(
            [XRAY_BINARY, 'run', '-c', config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(2)

        proxy_handler = urllib.request.ProxyHandler({
            'http': f'socks5h://127.0.0.1:{socks_port}',
            'https': f'socks5h://127.0.0.1:{socks_port}'
        })
        opener = urllib.request.build_opener(proxy_handler)
        response = opener.open(TEST_URL, timeout=TIMEOUT)
        return key, response.status == 204

    except:
        return key, False
    finally:
        if proc:
            proc.terminate()
            proc.wait()
        try:
            os.unlink(config_path)
        except:
            pass

def check_all(keys, max_workers=15):
    # Приоритет: vless+reality, trojan, vmess
    reality = [k for k in keys if k.startswith('vless://') and 'reality' in k.lower()]
    trojan = [k for k in keys if k.startswith('trojan://')]
    vmess = [k for k in keys if k.startswith('vmess://')]
    others = [k for k in keys if k.startswith('vless://') and 'reality' not in k.lower()]

    print(f"VLESS+Reality: {len(reality)}, Trojan: {len(trojan)}, VMess: {len(vmess)}, Другие: {len(others)}")

    sample = []
    sample += reality[:300]
    sample += trojan[:200]
    sample += vmess[:150]
    sample += others[:150]

    if len(sample) > MAX_CHECK:
        sample = sample[:MAX_CHECK]

    random.shuffle(sample)
    print(f"Проверяем через xray: {len(sample)} ключей")

    working = []
    total = len(sample)
    done = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_key, key): key for key in sample}
        for future in as_completed(futures):
            key, is_alive = future.result()
            done += 1
            if is_alive:
                working.append(key)
                print(f"[OK] {done}/{total} — рабочих: {len(working)}")
            elif done % 50 == 0:
                print(f"[..] {done}/{total} — рабочих: {len(working)}")

    print(f"\nИтого рабочих: {len(working)} из {total}")
    return working

if __name__ == '__main__':
    with open('output/raw.txt') as f:
        keys = [l.strip() for l in f if l.strip()]
    working = check_all(keys)
    with open('output/working.txt', 'w') as f:
        f.write('\n'.join(working))
