import requests
import base64
import re
import os

# Только протоколы с маскировкой — работают под белым списком
SUPPORTED_PROTOCOLS = ['vless://', 'trojan://']

# Признаки хорошего ключа для РФ
REQUIRED_FEATURES = ['reality', 'xtls', 'vision']

def load_sources():
    with open('sources.txt', 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def decode_base64_safe(data):
    try:
        padded = data + '=' * (4 - len(data) % 4)
        return base64.b64decode(padded).decode('utf-8', errors='ignore')
    except:
        return data

def is_good_key(key):
    """Проверяем что ключ подходит для белого списка РФ"""
    key_lower = key.lower()
    # Должен быть один из нужных протоколов
    if not any(key.startswith(p) for p in SUPPORTED_PROTOCOLS):
        return False
    # Должен содержать признаки маскировки
    has_feature = any(f in key_lower for f in REQUIRED_FEATURES)
    return has_feature

def extract_keys(text):
    keys = set()
    decoded = decode_base64_safe(text)
    for source in [text, decoded]:
        for line in source.splitlines():
            line = line.strip()
            if len(line) > 20 and is_good_key(line):
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
                print(f"[+] {url.split('/')[-1]} — найдено: {len(found)}")
                all_keys.update(found)
            else:
                print(f"[-] {url.split('/')[-1]} — статус: {r.status_code}")
        except Exception as e:
            print(f"[-] {url.split('/')[-1]} — ошибка: {e}")

    os.makedirs('output', exist_ok=True)
    with open('output/raw.txt', 'w') as f:
        f.write('\n'.join(all_keys))

    print(f"\nВсего Reality/XTLS ключей: {len(all_keys)}")
    return all_keys

if __name__ == '__main__':
    collect()
