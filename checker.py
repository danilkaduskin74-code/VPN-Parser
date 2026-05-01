import socket
import re
import base64
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

def parse_host_port(key):
    """Извлекает host и port из ключа"""
    try:
        if key.startswith('vmess://'):
            data = key[8:]
            padded = data + '=' * (4 - len(data) % 4)
            config = json.loads(base64.b64decode(padded).decode('utf-8'))
            return config.get('add'), int(config.get('port', 0))
        
        # vless, trojan, ss, hy2
        match = re.search(r'@([^:@]+):(\d+)', key)
        if match:
            return match.group(1), int(match.group(2))
    except:
        pass
    return None, None

def check_key(key, timeout=5):
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

def check_all(keys, max_workers=50):
    working = []
    total = len(keys)
    done = 0
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_key, key): key for key in keys}
        for future in as_completed(futures):
            key, is_alive = future.result()
            done += 1
            if is_alive:
                working.append(key)
            if done % 50 == 0:
                print(f"Проверено: {done}/{total}, рабочих: {len(working)}")
    
    print(f"\nРабочих ключей: {len(working)} из {total}")
    return working

if __name__ == '__main__':
    with open('output/raw.txt') as f:
        keys = [l.strip() for l in f if l.strip()]
    working = check_all(keys)
    with open('output/working.txt', 'w') as f:
        f.write('\n'.join(working))
