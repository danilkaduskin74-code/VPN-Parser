import base64
import os
from datetime import datetime

def build_subscription(input_file='output/working.txt', output_file='output/subscription.txt', limit=200):
    with open(input_file) as f:
        keys = [l.strip() for l in f if l.strip()]
    
    # Берём не больше limit ключей
    keys = keys[:limit]
    
    # Кодируем в base64 — стандартный формат подписки
    combined = '\n'.join(keys)
    encoded = base64.b64encode(combined.encode('utf-8')).decode('utf-8')
    
    with open(output_file, 'w') as f:
        f.write(encoded)
    
    # Также сохраняем читаемую версию с датой
    with open('output/info.txt', 'w') as f:
        f.write(f"Обновлено: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n")
        f.write(f"Ключей в подписке: {len(keys)}\n")
    
    print(f"Подписка собрана: {len(keys)} ключей → {output_file}")

if name == '__main__':
    build_subscription()
