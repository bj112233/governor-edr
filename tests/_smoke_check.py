"""Quick port-availability check used during smoke tests.

Probes localhost ports the bot depends on (KoboldCpp, MCP) so we can
decide whether `python main.py` can start cleanly.
"""

import socket


def probe(port: int, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


for name, port in [("KoboldCpp", 5001), ("MCP", 11123)]:
    state = "OPEN" if probe(port) else "closed"
    print(f"{name:<12} :{port}  ->  {state}")
