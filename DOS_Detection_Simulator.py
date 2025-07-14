# -------IM_VYADAW-------------
import time
import random

def simulate_network_traffic():
    return random.randint(10, 500)

if __name__ == "__main__":
    threshold = 300
    print("[+] Starting DoS detection simulation...")
    while True:
        traffic = simulate_network_traffic()
        print(f"Current traffic: {traffic} requests/sec")
        if traffic > threshold:
            print(f"[!] ALERT: High traffic detected! Possible DoS attack.")
        time.sleep(1)