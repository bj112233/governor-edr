"""Run inside Session 0 via schtasks — hits C2 API to trigger forced hunt."""
import httpx
import json
import sys

# Step 1: Login with Basic Auth to get Bearer token
try:
    r = httpx.post(
        "http://127.0.0.1:8765/api/auth/login",
        headers={"Authorization": "Basic YWRtaW46am5ONW0wY3pBcndkaEZ1OWRqUG56VzdkejA2Wjd2V0E="},
        timeout=10,
    )
    print(f"[Login] status={r.status_code} body={r.text[:200]}")
    if r.status_code != 200:
        # Try default creds from config
        sys.exit(1)
    token = r.json().get("token")
    if not token:
        print("[Login] No token in response")
        sys.exit(1)
    print(f"[Login] Got token: {token[:16]}...")
except Exception as e:
    print(f"[Login] Failed: {e}")
    sys.exit(1)

# Step 2: Trigger forced hunt
try:
    r = httpx.post(
        "http://127.0.0.1:8765/api/threat_hunter/trigger",
        headers={"Authorization": f"Bearer {token}"},
        json={"force": True},
        timeout=15,
    )
    print(f"[Trigger] status={r.status_code} body={r.text[:300]}")
except Exception as e:
    print(f"[Trigger] Failed: {e}")
    sys.exit(1)
