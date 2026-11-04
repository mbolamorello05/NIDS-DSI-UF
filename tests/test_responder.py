"""Tests du responder NIDS.

Lancer :   python -m pytest tests -v        (si pytest est installe)
     ou :  python tests/test_responder.py   (aucune dependance)

Les tests du demon utilisent un FAUX "nft" ecrit a la volee dans un dossier
temporaire : aucun vrai pare-feu n'est modifie. Ils necessitent Linux ; sous
Windows ils sont ignores (les tests du moteur de decision tournent partout).
"""
import importlib.util, inspect, json, os, pathlib, shutil, signal, subprocess, sys, tempfile, time

HERE = pathlib.Path(__file__).resolve().parent
RESPONDER = HERE.parent / "responder.py"
FAKE_NFT_SCRIPT = """#!/bin/sh
# Faux nft : enregistre chaque appel (et le script recu sur stdin) dans $NFT_LOG, puis reussit.
{ echo "ARGS: $*"; if [ "$1" = "-f" ]; then cat; fi; } >> "$NFT_LOG"
exit 0
"""
CAN_RUN_DAEMON = os.name != "nt" and shutil.which("sh") is not None


# ----------------------------------------------------------------- outils
def load(data_dir):
    """Charge une copie neuve du module, pointant sur data_dir."""
    os.environ["NIDS_DATA"] = str(data_dir)
    spec = importlib.util.spec_from_file_location(f"responder_{abs(hash(str(data_dir)))}", RESPONDER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class FakeFW:
    def __init__(self): self.calls = []
    def setup(self, active): return True
    def teardown(self): self.calls.append(("teardown",)); return True
    def block(self, ip, ttl): self.calls.append(("block", ip, int(ttl))); return True
    def unblock(self, ip): self.calls.append(("unblock", ip)); return True


def rec(ip, fam="ddos", proto=6, conf=0.99, proba=0.99, fine="syn_flood"):
    return {"verdict": "anomal", "src_ip": ip, "family_label": fam, "family_confidence": conf,
            "model1_proba_anomal": proba, "protocol": proto, "fine_label": fine}


def engine(r, mode="enforce", profile=None, **over):
    pol = r.load_policy()
    if profile:
        r.with_profile(pol, profile)
    pol["mode"] = mode
    pol.update(over)
    fw = FakeFW()
    return r.Engine(pol, fw, set(), persist=False), fw


def flood(e, ip, t=1000.0, n=20, **kw):
    for i in range(n):
        e.handle(rec(ip, **kw), t + i * 0.1)


# ----------------------------------------------------------------- moteur de decision
def test_ddos_threshold(tmp_path):
    r = load(tmp_path); e, fw = engine(r)
    flood(e, "10.0.0.5", n=19); assert fw.calls == []
    e.handle(rec("10.0.0.5"), 1002.0); assert fw.calls == [("block", "10.0.0.5", 60)]


def test_slow_flows_do_not_block(tmp_path):
    r = load(tmp_path); e, fw = engine(r)
    for i in range(40): e.handle(rec("10.0.0.6"), 1000 + i * 3)      # 1 flux / 3 s, fenetre de 30 s
    assert fw.calls == []


def test_scan_is_never_blocked(tmp_path):
    r = load(tmp_path); e, fw = engine(r)
    for i in range(500): e.handle(rec("10.0.0.7", "scan", fine="port_scan"), 1000 + i * 0.01)
    assert fw.calls == [] and e.stats["alert_only"] == 1


def test_udp_icmp_only_alert_by_default_but_configurable(tmp_path):
    r = load(tmp_path); e, fw = engine(r)
    for proto in (17, 1): flood(e, "10.0.0.8", n=100, proto=proto)
    assert fw.calls == []
    pol = r.load_policy(); pol["mode"] = "enforce"; pol["rules"]["ddos"]["protocols"] = [6, 17, 1]
    e2 = r.Engine(pol, FakeFW(), set(), persist=False); flood(e2, "10.0.0.8", n=30, proto=17)
    assert e2.fw.calls and e2.fw.calls[0][0] == "block"


def test_low_confidence_does_not_block(tmp_path):
    r = load(tmp_path); e, fw = engine(r)
    flood(e, "10.0.0.9", n=100, conf=0.80); flood(e, "10.0.0.9", t=2000, n=100, proba=0.5)
    assert fw.calls == []


def test_allowlist_ip_and_cidr(tmp_path):
    r = load(tmp_path); e, fw = engine(r, allowlist=["192.168.1.0/24", "10.9.9.9"])
    for ip in ("192.168.1.50", "10.9.9.9"): flood(e, ip, n=100)
    assert fw.calls == [] and e.stats["skip_allowlist"] == 2


def test_dry_run_never_touches_firewall(tmp_path):
    r = load(tmp_path); e, fw = engine(r, "dry-run")
    flood(e, "10.0.0.10", n=30); assert fw.calls == [] and e.stats["would_block"] == 1


def test_off_mode_does_nothing(tmp_path):
    r = load(tmp_path); e, fw = engine(r, "off"); flood(e, "10.0.0.11", n=50); assert fw.calls == [] and not e.blocked


def test_firewall_down_falls_back_to_dry_run(tmp_path):
    r = load(tmp_path); e, fw = engine(r); e.fw_ok = False
    flood(e, "10.0.0.12"); assert fw.calls == [] and e.stats["would_block"] == 1


def test_dry_to_enforce_drops_simulated_blocks(tmp_path):
    r = load(tmp_path); e, fw = engine(r, "dry-run"); flood(e, "10.0.0.13")
    p = r.load_policy(); p["mode"] = "enforce"; e.set_policy(p); assert "10.0.0.13" not in e.blocked


def test_circuit_breaker(tmp_path):
    r = load(tmp_path); e, fw = engine(r, max_active_blocks=2)
    for n in range(5): flood(e, f"10.1.0.{n}")
    assert len([c for c in fw.calls if c[0] == "block"]) == 2 and e.stats["circuit_breaker"] == 1


def test_expiry_and_escalation_in_strict_profile(tmp_path):
    r = load(tmp_path); e, fw = engine(r, profile="strict"); t = 1000.0; durations = []
    for n in range(6):
        flood(e, "10.0.0.14", t=t); e.unblock("10.0.0.14", t + 5); t += 100
    assert [c[2] for c in fw.calls if c[0] == "block"] == [600, 1200, 2400, 4800, 9600, 19200]


def test_demo_profile_has_constant_duration(tmp_path):
    r = load(tmp_path); e, fw = engine(r); t = 5000.0
    for n in range(6):
        flood(e, "10.0.0.15", t=t); e.unblock("10.0.0.15", t + 5); t += 100
    assert [c[2] for c in fw.calls if c[0] == "block"] == [60] * 6


def test_escalation_is_forgotten_after_a_quiet_day(tmp_path):
    r = load(tmp_path); e, fw = engine(r, profile="strict")
    flood(e, "10.0.0.16", t=1000); e.unblock("10.0.0.16", 1005)           # 600 s
    flood(e, "10.0.0.16", t=1200); e.unblock("10.0.0.16", 1205)           # recidive : 1200 s
    flood(e, "10.0.0.16", t=1200 + 1200 + 90000)                          # 25 h apres la fin du precedent
    assert [c[2] for c in fw.calls if c[0] == "block"] == [600, 1200, 600]


def test_manual_unblock_and_release_all(tmp_path):
    r = load(tmp_path); e, fw = engine(r)
    flood(e, "10.0.0.17"); flood(e, "10.0.0.18")
    assert e.unblock("10.0.0.17", 1005) and fw.calls[-1] == ("unblock", "10.0.0.17")
    assert e.release_all(1006, "test") == 1 and not e.blocked


def test_leaving_enforce_releases_real_blocks(tmp_path):
    r = load(tmp_path); e, fw = engine(r); flood(e, "10.0.0.19")
    p = r.load_policy(); p["mode"] = "dry-run"; e.set_policy(p)
    assert not e.blocked and ("unblock", "10.0.0.19") in fw.calls
    assert any(ev["event"] == "unblock" and "mode dry-run" in ev["reason"] for ev in e.events)


def test_defaults_and_profiles(tmp_path):
    r = load(tmp_path)
    assert r.current_profile(r.load_policy()) == "demo"
    assert r.current_profile(r.with_profile(r.load_policy(), "strict")) == "strict"
    q = r.with_profile(r.load_policy(), "strict"); q["rules"]["ddos"]["ttl_s"] = 123
    assert r.current_profile(q) == "custom"


# ----------------------------------------------------------------- validation de la politique
def test_sanitize_replaces_invalid_values(tmp_path):
    r = load(tmp_path)
    p = r.sanitize_policy({"mode": "banane", "max_ttl_s": -5, "max_active_blocks": True, "history_reset_s": "x",
                           "rules": {"ddos": {"action": "block", "min_events": "abc", "ttl_s": -1, "min_confidence": 7, "protocols": "tcp"},
                                     "scan": {"action": "tuer-tout"}, "poubelle": 5}})
    assert p["mode"] == "dry-run" and p["max_ttl_s"] == 60 and p["max_active_blocks"] == 50 and p["history_reset_s"] == 86400
    d = p["rules"]["ddos"]
    assert (d["min_events"], d["ttl_s"], d["min_confidence"], d["protocols"]) == (20, 60, 0.97, [6])
    assert p["rules"]["scan"] == {"action": "alert_only"} and "poubelle" not in p["rules"]


def test_sanitize_keeps_valid_values_and_handles_garbage(tmp_path):
    r = load(tmp_path)
    p = r.sanitize_policy({"mode": "enforce", "max_ttl_s": 123.5, "allowlist": ["10.0.0.0/8", 5],
                           "rules": {"ddos": {"action": "block", "min_events": 7, "ttl_s": 60.0, "window_s": 15}}})
    assert p["mode"] == "enforce" and p["max_ttl_s"] == 123.5 and p["allowlist"] == ["10.0.0.0/8", "5"]
    assert p["rules"]["ddos"]["min_events"] == 7 and p["rules"]["ddos"]["ttl_s"] == 60 and p["rules"]["ddos"]["window_s"] == 15
    for garbage in (None, [], "texte", 42):
        assert r.sanitize_policy(garbage)["mode"] == "dry-run"
    assert r.sanitize_policy({"max_ttl_s": float("nan")})["max_ttl_s"] == 60
    assert r.sanitize_policy({"rules": []})["rules"] == r.DEFAULT_POLICY["rules"]


def test_trim_log(tmp_path):
    r = load(tmp_path); p = tmp_path / "events.jsonl"
    p.write_text("".join(json.dumps({"i": i}) + "\n" for i in range(50000)))
    assert r.trim_log(str(p), max_bytes=100_000, keep=100) is True
    lines = p.read_text().splitlines()
    assert len(lines) == 100 and json.loads(lines[-1]) == {"i": 49999} and all(json.loads(l) for l in lines)
    assert r.trim_log(str(p), max_bytes=100_000, keep=100) is False      # deja petit : rien a faire


def test_commands_and_status(tmp_path):
    r = load(tmp_path); os.makedirs(r.COMMANDS_DIR); r.write_json(r.POLICY_PATH, r.DEFAULT_POLICY)
    e, fw = engine(r); flood(e, "10.0.0.20"); flood(e, "10.0.0.21")
    r.send_command("unblock", ip="10.0.0.20", source="dashboard")
    r.send_command("set_mode", value="enforce", source="dashboard")
    r.send_command("set_profile", value="strict", source="dashboard")
    r.send_command("set_mode", value="n'importe quoi", source="dashboard")
    r.send_command("rm_rf", value="/", source="dashboard")
    open(os.path.join(r.COMMANDS_DIR, "0-garbage.json"), "w").write("{pas du json")
    assert r.process_commands(e, 3000.0) is True
    pol = r.read_json(r.POLICY_PATH, {})
    assert "10.0.0.20" not in e.blocked and "10.0.0.21" in e.blocked
    assert pol["mode"] == "enforce" and r.current_profile(pol) == "strict"
    assert os.listdir(r.COMMANDS_DIR) == [] and sum(ev["event"] == "config" for ev in e.events) == 2
    r.send_command("unblock_all", source="dashboard"); r.process_commands(e, 3001.0); assert not e.blocked
    e.fw_ok = True; e.set_policy(r.load_policy()); r.write_status(e, 123.0, 100.0)
    st = r.read_json(r.STATUS_PATH, {})
    assert st["mode"] == "enforce" and st["profile"] == "strict" and st["enforcing"] and st["ts"] == 123.0
    assert st["started_at"] == 100.0 and st["stopped"] is False and "stats" in st and "rules" in st
    e.fw_ok = False; r.write_status(e, 124.0); assert r.read_json(r.STATUS_PATH, {})["enforcing"] is False


# ----------------------------------------------------------------- demon complet (faux nft)
class Daemon:
    def __init__(self, data):
        self.data = pathlib.Path(data); self.nft_log = self.data / "nft.log"
        self.nft_log.touch(); (self.data / "config").mkdir(exist_ok=True); (self.data / "detections_v6.jsonl").touch()
        self.bin = self.data / "fake_bin"; self.bin.mkdir(exist_ok=True)
        fake = self.bin / "nft"; fake.write_text(FAKE_NFT_SCRIPT, newline="\n"); fake.chmod(0o755)
        self.proc = None

    def start(self):
        env = dict(os.environ, NIDS_DATA=str(self.data), NFT_LOG=str(self.nft_log), PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}")
        self.proc = subprocess.Popen([sys.executable, str(RESPONDER)], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert self.wait(lambda: self.status() is not None and not self.status().get("stopped") and self.status()["pid"] == self.proc.pid), "le demon ne demarre pas"
        return self

    def stop(self, sig=signal.SIGTERM):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(sig)
            try: self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired: self.proc.kill(); self.proc.wait()
        return self.proc.returncode if self.proc else None

    def status(self):
        try: return json.loads((self.data / "responder_status.json").read_text())
        except (OSError, ValueError): return None

    def blocks(self):
        try: return json.loads((self.data / "blocks.json").read_text()).get("blocks", {})
        except (OSError, ValueError): return {}

    def nft(self): return self.nft_log.read_text()

    def cmd(self, name, **kw):
        d = self.data / "config" / "commands"; d.mkdir(parents=True, exist_ok=True)
        tmp = d / f".{time.time_ns()}.tmp"; tmp.write_text(json.dumps(dict(cmd=name, source="test", **kw))); os.replace(tmp, str(tmp)[:-4] + ".json")

    def policy(self, **kw): (self.data / "config" / "response_policy.json").write_text(json.dumps(kw))

    def send(self, lines):
        with open(self.data / "detections_v6.jsonl", "a") as f:
            for l in lines: f.write((l if isinstance(l, str) else json.dumps(l)) + "\n")

    def flood(self, ip, n=25):
        self.send({**rec(ip), "src_port": 1000 + i, "dst_ip": "192.168.148.149", "dst_port": 80, "timestamp": "2026-11-01T10:00:00+00:00"} for i in range(n))

    @staticmethod
    def wait(cond, timeout=8):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if cond(): return True
            time.sleep(0.15)
        return False


def test_daemon_full_cycle(tmp_path):
    if not CAN_RUN_DAEMON: return
    d = Daemon(tmp_path).start()
    try:
        s = d.status(); assert s["mode"] == "dry-run" and s["profile"] == "demo" and s["fw_ok"] and not s["enforcing"]
        t0 = d.status()["ts"]; time.sleep(1.5); assert d.status()["ts"] > t0                  # battement de coeur
        d.flood("192.168.148.139"); assert d.wait(lambda: "192.168.148.139" in d.blocks())
        assert d.blocks()["192.168.148.139"]["dry_run"] is True and "add element" not in d.nft()
        d.cmd("set_mode", value="enforce"); assert d.wait(lambda: d.status()["mode"] == "enforce")
        assert d.wait(lambda: d.blocks() == {})                                              # le bloc simule disparait
        d.flood("192.168.148.139")
        assert d.wait(lambda: "add element inet nids blocked { 192.168.148.139 timeout 60s }" in d.nft())
        assert d.wait(lambda: d.status()["active_blocks"] == 1 and d.status()["enforcing"])
        d.cmd("set_profile", value="strict"); assert d.wait(lambda: d.status()["profile"] == "strict")
        d.flood("192.168.148.150"); assert d.wait(lambda: "192.168.148.150" in d.blocks())
        b = d.blocks()["192.168.148.150"]; assert 590 <= b["until"] - b["since"] <= 601
        d.cmd("unblock", ip="192.168.148.150")
        assert d.wait(lambda: "192.168.148.150" not in d.blocks() and "delete element inet nids blocked { 192.168.148.150 }" in d.nft())
        d.cmd("set_mode", value="dry-run"); assert d.wait(lambda: d.status()["mode"] == "dry-run" and d.blocks() == {})
        assert "delete element inet nids blocked { 192.168.148.139 }" in d.nft()
        events = [json.loads(l)["event"] for l in (tmp_path / "response_events.jsonl").read_text().splitlines()]
        assert {"would_block", "block", "unblock", "config"} <= set(events)
    finally:
        d.stop()


def test_daemon_survives_garbage_input(tmp_path):
    if not CAN_RUN_DAEMON: return
    d = Daemon(tmp_path); d.policy(mode="enforce"); d.start()
    try:
        d.send(['{"verdict":"anomal","src_ip":"1.2.3.4","family_label":"ddos","family_confidence":"abc","protocol":6}',
                '{"verdict":"anomal","src_ip":["x"],"family_label":"ddos"}', "[1,2,3]", '"une chaine"', "null", "{pas du json", "42"])
        assert d.wait(lambda: d.status()["stats"].get("erreurs", 0) >= 1)
        d.flood("192.168.148.139")                                                           # le demon doit toujours proteger
        assert d.wait(lambda: "add element inet nids blocked { 192.168.148.139" in d.nft())
        assert d.proc.poll() is None
    finally:
        d.stop()


def test_daemon_tolerates_invalid_policy_file(tmp_path):
    if not CAN_RUN_DAEMON: return
    d = Daemon(tmp_path); d.policy(mode="enforce", max_ttl_s="beaucoup", rules={"ddos": {"action": "block", "min_events": "x"}}); d.start()
    try:
        assert d.status()["mode"] == "enforce" and d.status()["max_ttl_s"] == 60
        d.flood("192.168.148.139"); assert d.wait(lambda: "192.168.148.139" in d.blocks())
    finally:
        d.stop()


def test_graceful_shutdown_removes_rules_and_restart_restores_blocks(tmp_path):
    if not CAN_RUN_DAEMON: return
    d = Daemon(tmp_path); d.policy(mode="enforce"); d.start()
    try:
        d.flood("192.168.148.139"); assert d.wait(lambda: "add element inet nids blocked { 192.168.148.139 timeout 60s }" in d.nft())
        t0 = time.time(); code = d.stop(signal.SIGTERM); assert code == 0, f"code de sortie {code}"
        assert time.time() - t0 < 5, "l'arret doit etre rapide (avant : 10 s puis SIGKILL)"
        log = d.nft(); assert log.rfind("delete table inet nids") > log.find("add element"), "la table doit etre retiree a l'arret"
        assert d.status()["stopped"] is True and "192.168.148.139" in d.blocks()          # l'etat est conserve
        time.sleep(2)
        d.start()                                                                          # redemarrage : le blocage est remis en place
        assert d.wait(lambda: d.nft().count("add element inet nids blocked { 192.168.148.139") == 2)
        ttl = int(d.nft().split("blocked { 192.168.148.139 timeout ")[-1].split("s")[0])
        assert 40 <= ttl < 60, f"duree restante attendue < 60 s, obtenue {ttl}"
    finally:
        d.stop()


# ----------------------------------------------------------------- lanceur sans pytest
if __name__ == "__main__":
    failed, count = [], 0
    for name, fn in sorted((n, f) for n, f in globals().items() if n.startswith("test_") and callable(f)):
        count += 1
        tmp = pathlib.Path(tempfile.mkdtemp())
        t0 = time.time()
        try:
            fn(tmp) if inspect.signature(fn).parameters else fn()
            print(f"ok   {name} ({time.time() - t0:.1f} s)")
        except Exception as exc:
            failed.append(name); print(f"ECHEC {name} : {type(exc).__name__}: {exc}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{count - len(failed)}/{count} tests reussis" + ("" if not failed else f" ; echecs : {failed}"))
    sys.exit(1 if failed else 0)
