import requests
import base64
import re
import os

SUPPORTED_PROTOCOLS = ['vless://', 'vmess://', 'trojan://', 'ss://', 'hy2://', 'hysteria2://']

def load_sources():
    with open('sources.txt', 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def decode_base64_safe(data):
    try:
        padded = data + '=' * (4 - len(data) % 4)
        return base64.b64decode(padded).decode('utf-8', errors='ignore')
    except:
        return data

def extract_keys(text):
    keys = set()
    # Попытка декодировать base64
    decoded = decode_base64_safe(text)
    for source in [text, decoded]:
        for line in source.splitlines():
            line = line.strip()
            for proto in SUPPORTED_PROTOCOLS:
                if line.startswith(proto) and len(line) > 20:
                    keys.add(line)
    return keys

def collect():
    sources = load_sources()
    all_keys = set()
    for url in sources:
        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                found = extract_keys(r.text)
                print(f"[+] {url} — найдено: {len(found)}")
                all_keys.update(found)
        except Exception as e:
            print(f"[-] {url} — ошибка: {e}")
    
    os.makedirs('output', exist_ok=True)
    with open('output/raw.txt', 'w') as f:
        f.write('\n'.join(all_keys))
    print(f"\nВсего собрано: {len(all_keys)} ключей")
    return all_keys

if __name__ == '__main__':
    collect()
