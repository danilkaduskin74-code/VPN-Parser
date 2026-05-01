import subprocess
import os
import json
import base64
import re
import tempfile
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

XRAY_BINARY = './xray'
TEST_URL = 'http://www.gstatic.com/generate_204'
TIMEOUT = 10

def install_xray():
    if os.path.exists(XRAY_BINARY):
        return True
    try:
        os.system('wget -q https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -O xray.zip')
        os.system('unzip -q xray.zip xray -d .')
        os.system('chmod +x xray')
        return os.path.exists(XRAY_BINARY)
    except:
        return False

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

def make_xray_config(key, socks_port):
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": False}
        }],
        "outbounds": [{
            "protocol": "freedom",
            "tag": "direct"
        }]
    }

def build_outbound(key):
    try:
        if key.startswith('vless://'):
            match = re.match(r'vless://([^@]+)@([^:]+):(\d+)\??(.*)#?(.*)', key)
            if not match:
                return None
            uuid, host, port, params, _ = match.groups()
            param_dict = dict(p.split('=') for p in params.split('&') if '=' in p)
            outbound = {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": int(port),
                        "users": [{"id": uuid, "encryption": "none"}]
                    }]
                },
                "streamSettings": {
                    "network": param_dict.get("type", "tcp"),
                    "security": param_dict.get("security", "none")
                }
            }
            if param_dict.get("security") == "reality":
                outbound["streamSettings"]["realitySettings"] = {
                    "fingerprint": param_dict.get("fp", "chrome"),
                    "serverName": param_dict.get("sni", host),
                    "publicKey": param_dict.get("pbk", ""),
                    "shortId": param_dict.get("sid", ""),
                    "spiderX": param_dict.get("spx", "")
                }
            elif param_dict.get("security") == "tls":
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": param_dict.get("sni", host),
                    "allowInsecure": True
                }
            return outbound

        elif key.startswith('trojan://'):
            match = re.match(r'trojan://([^@]+)@([^:]+):(\d+)\??(.*)#?(.*)', key)
            if not match:
                return None
            password, host, port, params, _ = match.groups()
            param_dict = dict(p.split('=') for p in params.split('&') if '=' in p)
            return {
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
                    "security": param_dict.get("security", "tls"),
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
            return {
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
                "streamSettings": {
                    "network": c.get("net", "tcp"),
                    "security": c.get("tls", "none"),
                    "tlsSettings": {"allowInsecure": True} if c.get("tls") == "tls" else {}
                }
            }
    except:
        pass
    return None

def check_key(key):
    outbound = build_outbound(key)
    if not outbound:
        return key, False

    socks_port = get_free_port()
    config = make_xray_config(key, socks_port)
    config["outbounds"].insert(0, outbound)
    config["outbounds"][0]["tag"] = "proxy"
    config["inbounds"][0]["tag"] = "socks-in"
    config["routing"] = {
        "rules": [{"type": "field", "inboundTag": ["socks-in"], "outboundTag": "proxy"}]
    }

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
        import time
        time.sleep(2)

        import urllib.request
        proxies = {'http': f'socks5h://127.0.0.1:{socks_port}'}
        proxy_handler = urllib.request.ProxyHandler(proxies)
        opener = urllib.request.build_opener(proxy_handler)
        opener.addheaders = [('User-agent', 'Mozilla/5.0')]
        urllib.request.install_opener(opener)

        response = opener.open(TEST_URL, timeout=TIMEOUT)
        return key, response.status == 204

    except:
        return key, False
    finally:
        if proc:
            proc.terminate()
        os.unlink(config_path)

def check_all(keys, max_workers=20):
    working = []
    total = len(keys)
    done = 0

    print(f"Устанавливаем xray...")
    if not install_xray():
        print("Xray не установлен, используем TCP-проверку")
        from checker_tcp import check_all as tcp_check
        return tcp_check(keys)

    print(f"Проверяем {total} ключей через xray...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_key, key): key for key in keys}
        for future in as_completed(futures):
            key, is_alive = future.result()
            done += 1
            if is_alive:
                working.append(key)
            if done % 20 == 0:
                print(f"Проверено: {done}/{total}, рабочих: {len(working)}")

    print(f"\nРабочих ключей: {len(working)} из {total}")
    return working

if __name__ == '__main__':
    with open('output/raw.txt') as f:
        keys = [l.strip() for l in f if l.strip()]
    working = check_all(keys)
    with open('output/working.txt', 'w') as f:
        f.write('\n'.join(working))
