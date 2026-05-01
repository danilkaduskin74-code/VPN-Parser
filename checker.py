import socket
import re
import base64
import json
import random
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

def score_key(key):
    """Оцениваем качество ключа по параметрам"""
    score = 0
    key_lower = key.lower()

    # Лучшие протоколы для РФ
    if 'reality' in key_lower:
        score += 10
    if key.startswith('vless://'):
        score += 5
    if key.startswith('trojan://'):
        score += 4
    if key.startswith('vmess://'):
        score += 2

    # Хорошие параметры
    if 'xtls' in key_lower or 'flow=xtls' in key_lower:
        score += 5
    if 'fp=chrome' in key_lower or 'fp=firefox' in key_lower:
        score += 3
    if 'sni=' in key_lower:
        score += 2
    if 'pbk=' in key_lower:
        score += 3

    # Плохие признаки
    if '127.0.0.1' in key or 'localhost' in key:
        score -= 20
    if ':80' in key and 'reality' not in key_lower:
        score -= 2

    # Порты которые обычно не блокируют
    try:
        _, port = parse_host_port(key)
        if port in [443, 8443, 2053, 2083, 2087, 2096]:
            score += 3
            # Исключаем ключи с плохим скором полностью
        if score < 3:
            return key, False, 0
        elif port in [80, 8080]:
            score -= 1
    except:
        pass

    return score

def tcp_check(key, timeout=3):
    host, port = parse_host_port(key)
    if not host or not port:
        return key, False, 0
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        alive = result == 0
        return key, alive, score_key(key) if alive else 0
    except:
        return key, False, 0

def check_all(keys, max_workers=150):
    # Фильтруем мусор сразу
    keys = [k for k in keys if any(k.startswith(p) for p in
            ['vless://', 'trojan://', 'vmess://', 'ss://'])]

    # Сортируем по оценке — лучшие идут первыми на проверку
    keys_scored = [(k, score_key(k)) for k in keys]
    keys_scored.sort(key=lambda x: x[1], reverse=True)
    keys = [k for k, s in keys_scored]

    # Берём топ 1500 по оценке
    keys = keys[:2000]
    print(f"Отобрано для проверки: {len(keys)}")

    results = []
    total = len(keys)
    done = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(tcp_check, key): key for key in keys}
        for future in as_completed(futures):
            key, alive, score = future.result()
            done += 1
            if alive:
                results.append((key, score))
            if done % 150 == 0:
                print(f"Проверено: {done}/{total}, живых: {len(results)}")

    # Сортируем результат — лучшие ключи первыми
    results.sort(key=lambda x: x[1], reverse=True)
    working = [k for k, s in results]

    print(f"\nЖивых серверов: {len(working)} из {total}")
    print(f"Топ протоколы: reality={sum(1 for k in working if 'reality' in k.lower())}, "
          f"trojan={sum(1 for k in working if k.startswith('trojan://'))}, "
          f"vmess={sum(1 for k in working if k.startswith('vmess://'))}")
    return working

if __name__ == '__main__':
    with open('output/raw.txt') as f:
        keys = [l.strip() for l in f if l.strip()]
    working = check_all(keys)
    with open('output/working.txt', 'w') as f:
        f.write('\n'.join(working))
