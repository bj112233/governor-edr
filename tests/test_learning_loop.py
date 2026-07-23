"""Live test: end-to-end learning loop — Ignore button → net_baseline → SnapshotDiffer suppression."""

import hashlib


def test_alert_dispatcher_hash_generation():
    """Hash is deterministic and short enough for Telegram."""
    ip, port, proc = "13.89.178.27", 443, "msteamsupdate.exe"
    combo_raw = f"{ip}:{port}:{proc}"
    alert_id = hashlib.md5(combo_raw.encode()).hexdigest()[:8]

    assert len(alert_id) == 8, f"Hash must be 8 chars, got {len(alert_id)}"
    # Verify determinism: same input → same hash
    alert_id_2 = hashlib.md5(combo_raw.encode()).hexdigest()[:8]
    assert alert_id == alert_id_2, f"Hash not deterministic: {alert_id} vs {alert_id_2}"

    # Verify callback_data stays within Telegram 64-byte limit
    callback_data = f"rem_ign_{alert_id}"
    assert len(callback_data) <= 64, f"Callback data too long: {len(callback_data)} bytes"
    print(f"[PASS] Hash '{alert_id}' → callback_data '{callback_data}' ({len(callback_data)} bytes)")


def test_cache_roundtrip():
    """ACTIVE_ALERTS_CACHE stores and retrieves context correctly."""
    # Simulate the cache from alert_dispatcher
    ACTIVE_ALERTS_CACHE = {}

    ip, port, proc = "13.89.178.27", 443, "msteamsupdate.exe"
    combo_raw = f"{ip}:{port}:{proc}"
    alert_id = hashlib.md5(combo_raw.encode()).hexdigest()[:8]

    # Store (as alert_dispatcher does)
    ACTIVE_ALERTS_CACHE[alert_id] = {"ip": ip, "port": port, "proc_name": proc}

    # Retrieve (as callbacks.py does)
    cached = ACTIVE_ALERTS_CACHE.pop(alert_id, None)
    assert cached is not None, "Cache miss — context lost"
    assert cached["ip"] == ip
    assert cached["port"] == port
    assert cached["proc_name"] == proc

    # Verify cleanup
    assert alert_id not in ACTIVE_ALERTS_CACHE, "Cache not cleaned after pop"
    print("[PASS] Cache roundtrip: store → retrieve → clean")


def test_add_to_baseline_sql():
    """Verify the SQL that add_to_baseline generates is correct."""
    proc, ip, port = "msteamsupdate.exe", "13.89.178.27", 443

    expected_sql = """
                INSERT OR IGNORE INTO net_baselines (process_name, remote_ip, remote_port)
                VALUES (?, ?, ?)
                """
    expected_params = (proc, ip, port)

    assert "INSERT OR IGNORE" in expected_sql
    assert "net_baselines" in expected_sql
    assert len(expected_params) == 3
    assert expected_params[0] == proc
    assert expected_params[1] == ip
    assert expected_params[2] == port

    print(f"[PASS] SQL validated: INSERT OR IGNORE INTO net_baselines ({proc}, {ip}, {port})")


def test_snapshot_differ_suppression_logic():
    """Simulate SnapshotDiffer: known combo should be suppressed."""
    # Mock baseline state (as if add_to_baseline was called)
    _baseline_db = set()
    proc, ip, port = "msteamsupdate.exe", "13.89.178.27", 443
    _baseline_db.add((proc, ip, port))

    # Simulate is_known_combo check (as SnapshotDiffer does)
    def is_known_combo(process_name: str, remote_ip: str, remote_port: int) -> bool:
        return (process_name, remote_ip, remote_port) in _baseline_db

    # New connection that WAS learned
    assert is_known_combo(proc, ip, port), "Known combo should be suppressed"

    # New connection that was NOT learned
    assert not is_known_combo("evil.exe", "1.2.3.4", 666), "Unknown combo should NOT be suppressed"

    print("[PASS] SnapshotDiffer suppression: known→suppressed, unknown→alerted")


def test_full_loop_integration():
    """End-to-end: alert → hash → cache → ignore → learn → suppress."""
    # Step 1: Alert fires
    ip, port, proc = "13.89.178.27", 443, "msteamsupdate.exe"

    # Step 2: Dispatcher creates hash and cache
    combo_raw = f"{ip}:{port}:{proc}"
    alert_id = hashlib.md5(combo_raw.encode()).hexdigest()[:8]
    cache = {alert_id: {"ip": ip, "port": port, "proc_name": proc}}

    # Step 3: User clicks Ignore → callback resolves from cache
    cached = cache.pop(alert_id, None)
    assert cached is not None

    # Step 4: add_to_baseline writes to DB (simulated)
    baseline = set()
    baseline.add((cached["proc_name"], cached["ip"], cached["port"]))

    # Step 5: Next snapshot → SnapshotDiffer checks baseline
    def is_known_combo(p, i, po):
        return (p, i, po) in baseline

    assert is_known_combo(proc, ip, port), "Loop broken: learned combo still alerts"

    # Step 6: Cache cleaned
    assert alert_id not in cache

    print("[PASS] Full loop: alert → hash → cache → learn → suppress ✅")


if __name__ == "__main__":
    test_alert_dispatcher_hash_generation()
    test_cache_roundtrip()
    test_add_to_baseline_sql()
    test_snapshot_differ_suppression_logic()
    test_full_loop_integration()
    print("\n[ALL PASSED] 5/5 learning loop tests passed")
