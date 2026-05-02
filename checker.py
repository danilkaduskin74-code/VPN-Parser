import socket
import re
import base64
import json
from concurrent.futures import ThreadPoolExecutor, as_completed


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


def parse_params(key):
    try:
        match = re.search(r'\?([^#]*)', key)
        if not match:
            return {}
        return dict(p.split('=', 1) for p in match.group(1).split('&') if '=' in p)
    except:
        return {}


def score_key(key):
    score = 0
    key_lower = key.lower()
    params = parse_params(key)

    if 'reality' in key_lower:
        score += 15
    if 'xtls-rprx-vision' in key_lower:
        score += 10
    if params.get('flow') == 'xtls-rprx-vision':
        score += 10

    sni = params.get('sni', '').lower()
    if any(ru in sni for ru in ['userapi', 'vk.com', 'vk.me', 'ok.ru', 'yandex', 'mail.ru']):
        score += 8
    if any(s in sni for s in ['apple', 'microsoft', 'amazon', 'google', 'cloudflare']):
        score += 5

    fp = params.get('fp', '').lower()
    if fp in ['chrome', 'firefox', 'safari']:
        score += 4
    elif fp == 'qq':
        score += 2

    if params.get('pbk'):
        score += 3

    try:
        _, port = parse_host_port(key)
        if port in [443, 8443, 2053, 2083, 2087, 2096]:
            score += 5
        elif port in [80, 8080]:
            score -= 3
    except:
        pass

    if '127.0.0.1' in key or 'localhost' in key:
        score -= 50
    if not params.get('pbk') and 'reality' in key_lower:
        score -= 5

    return score


def tcp_check(key, timeout=4):
    host, port = parse_host_port(key)
    if not host or not port:
        return key, False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return key, result == 0
    except:
        return key, False


def check_all(keys, max_workers=150):
    keys = [k for k in keys if any(k.startswith(p) for p in ['vless://', 'trojan://'])]
    print(f"Всего ключей: {len(keys)}")

    keys = [k for k in keys if score_key(k) >= 10]
    print(f"После фильтрации: {len(keys)}")

    keys.sort(key=lambda k: score_key(k), reverse=True)
    keys = keys[:1000]
    print(f"Отобрано для проверки: {len(keys)}")

    working = []
    total = len(keys)
    done = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(tcp_check, key): key for key in keys}
        for future in as_completed(futures):
            key, alive = future.result()
            done += 1
            if alive:
                working.append(key)
            if done % 100 == 0:
                print(f"Проверено: {done}/{total}, живых: {len(working)}")

    working.sort(key=lambda k: score_key(k), reverse=True)

    reality_count = sum(1 for k in working if 'reality' in k.lower())
    vision_count = sum(1 for k in working if 'xtls-rprx-vision' in k.lower())

    print(f"\nЖивых: {len(working)} из {total}")
    print(f"Reality: {reality_count}")
    print(f"XTLS-Vision: {vision_count}")
    return working


if __name__ == '__main__':
    with open('output/raw.txt') as f:
        keys = [l.strip() for l in f if l.strip()]
    working = check_all(keys)
    with open('output/working.txt', 'w') as f:
        f.write('\n'.join(working))
