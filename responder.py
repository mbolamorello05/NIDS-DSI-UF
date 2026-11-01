#!/usr/bin/env python3
"""Responder NIDS -- reponse graduee et securisee aux detections.

Lit detections_v6.jsonl, applique une politique (response_policy.json) et, en
mode "enforce", bloque temporairement des IP via nftables. Tourne dans son
propre conteneur (network_mode: host + NET_ADMIN) : le detecteur reste passif.

Modes : off | dry-run (defaut : journalise "bloquerait", ne touche a rien) | enforce
"""
import argparse, copy, ipaddress, json, os, socket, struct, subprocess, sys, time
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone

DATA = os.environ.get("NIDS_DATA", "/data")
LOG_PATH = f"{DATA}/detections_v6.jsonl"
POLICY_PATH = f"{DATA}/config/response_policy.json"
UNBLOCK_PATH = f"{DATA}/config/unblock_requests.json"
STATE_PATH = f"{DATA}/blocks.json"
EVENTS_PATH = f"{DATA}/response_events.jsonl"

# Deux profils de duree de blocage :
#   demo   (defaut) : blocage de 60 s, sans escalade -> permet de rejouer des
#                     attaques depuis la meme machine sans l'exclure durablement.
#   strict          : 10 / 15 min, doublees a chaque recidive, plafond 24 h
#                     (exclusion plus severe, adaptee a un usage en production).
PROFILES = {
    "demo":   {"max_ttl_s": 60,    "ttl_s": {"ddos": 60,  "brute_force": 60}},
    "strict": {"max_ttl_s": 86400, "ttl_s": {"ddos": 600, "brute_force": 900}},
}

DEFAULT_POLICY = {
    "mode": "dry-run",
    "allowlist": [],              # IP/CIDR jamais bloquees (scanners du SOC, poste admin...)
    "max_active_blocks": 50,      # disjoncteur : au-dela, plus aucun blocage automatique
    "max_ttl_s": PROFILES["demo"]["max_ttl_s"],   # plafond de la duree (escalade comprise)
    "rules": {
        # Un scan peut etre legitime (SOC, audit) : on alerte, on ne bloque pas.
        "scan": {"action": "alert_only"},
        "brute_force": {"action": "block", "min_confidence": 0.95, "min_proba": 0.9,
                        "min_events": 5, "window_s": 60,
                        "ttl_s": PROFILES["demo"]["ttl_s"]["brute_force"], "protocols": [6]},
        "ddos": {"action": "block", "min_confidence": 0.97, "min_proba": 0.9,
                 "min_events": 20, "window_s": 30,
                 "ttl_s": PROFILES["demo"]["ttl_s"]["ddos"], "protocols": [6]},
    },
}


# ------------------------------------------------------------------ utilitaires
def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="seconds")

def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

def nets(values):
    out = set()
    for v in values:
        try:
            out.add(ipaddress.ip_network(str(v), strict=False))
        except ValueError:
            print(f"[responder] allowlist : entree ignoree {v!r}", flush=True)
    return out

def auto_protected():
    """Machine elle-meme, passerelle par defaut, serveurs DNS : jamais bloques."""
    found = {"127.0.0.1"}
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            found |= {a.address for a in addrs if a.family == socket.AF_INET}
    except Exception:
        pass
    try:
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000":
                found.add(socket.inet_ntoa(struct.pack("<L", int(f[2], 16))))
    except Exception:
        pass
    try:
        for line in open("/etc/resolv.conf"):
            p = line.split()
            if len(p) >= 2 and p[0] == "nameserver":
                found.add(p[1])
    except Exception:
        pass
    return nets(found)

def load_policy():
    user = read_json(POLICY_PATH, {})
    p = copy.deepcopy(DEFAULT_POLICY)
    p.update(user)
    if p["mode"] not in ("off", "dry-run", "enforce"):
        p["mode"] = "dry-run"
    return p


# ------------------------------------------------------------------ pare-feu
class NullFirewall:
    def setup(self, active): return True
    def block(self, ip, ttl): return True
    def unblock(self, ip): return True

class NftFirewall:
    """Table dediee 'inet nids' : jamais touchee aux regles Docker/ufw existantes.
    Le set a un 'timeout' : le noyau retire lui-meme l'IP a l'expiration."""
    RULESET = """
table inet nids {
  set blocked { type ipv4_addr; flags timeout; }
  chain input   { type filter hook input   priority -10; policy accept; ip saddr @blocked drop; }
  chain forward { type filter hook forward priority -10; policy accept; ip saddr @blocked drop; }
}
"""
    def _nft(self, script):
        try:
            r = subprocess.run(["nft", "-f", "-"], input=script, text=True, capture_output=True)
        except FileNotFoundError:
            print("[responder] ERREUR : binaire nft introuvable", flush=True)
            return False
        if r.returncode:
            print(f"[responder] ERREUR nft : {r.stderr.strip()}", flush=True)
        return r.returncode == 0

    def setup(self, active):
        try:
            subprocess.run(["nft", "delete", "table", "inet", "nids"], capture_output=True)
        except FileNotFoundError:
            pass
        ok = self._nft(self.RULESET)
        if ok:
            for ip, ttl in active.items():      # restaure apres redemarrage
                self.block(ip, ttl)
        return ok

    def block(self, ip, ttl):
        return self._nft(f"add element inet nids blocked {{ {ip} timeout {int(ttl)}s }}")

    def unblock(self, ip):
        return self._nft(f"delete element inet nids blocked {{ {ip} }}")


# ------------------------------------------------------------------ moteur de decision
class Engine:
    def __init__(self, policy, fw, protected, persist=True, fw_ok=True):
        self.fw, self.auto_protected, self.persist, self.fw_ok = fw, protected, persist, fw_ok
        self.blocked = {}                 # ip -> infos du blocage en cours
        self.history = Counter()          # ip -> nb de blocages passes (escalade)
        self.windows = defaultdict(deque)
        self.throttle = {}
        self.stats = Counter()
        self.events = []                  # conserve seulement hors persistance (replay)
        self.set_policy(policy)

    def set_policy(self, policy):
        previous = getattr(self, "policy", {}).get("mode")
        self.policy = policy
        self.allow = nets(policy["allowlist"]) | self.auto_protected
        if policy["mode"] == "enforce" and previous != "enforce":
            # les blocages "simules" ne deviennent pas reels a posteriori
            self.blocked = {k: v for k, v in self.blocked.items() if not v["dry_run"]}

    def is_protected(self, addr):
        return any(addr in n for n in self.allow)

    def event(self, now, kind, ip, quiet=False, **kw):
        ev = {"ts": iso(now), "event": kind, "ip": ip, **kw}
        self.stats[kind] += 1
        if self.persist:
            os.makedirs(os.path.dirname(EVENTS_PATH), exist_ok=True)
            with open(EVENTS_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            if not quiet:
                print(f"[responder] {kind} {ip} {kw.get('family', '')} {kw.get('reason', '')}", flush=True)
        else:
            self.events.append(ev)

    def once(self, key, now, every=60):
        if now - self.throttle.get(key, 0) < every:
            return False
        self.throttle[key] = now
        return True

    def handle(self, rec, now):
        if self.policy["mode"] == "off" or rec.get("verdict") != "anomal":
            return
        fam, ip = rec.get("family_label"), rec.get("src_ip")
        rule = self.policy["rules"].get(fam)
        if not rule or not ip:
            return
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return
        if addr.version != 4:
            return
        if self.is_protected(addr):
            if self.once(("skip", ip), now, 300):
                self.event(now, "skip_allowlist", ip, family=fam)
            return
        if ip in self.blocked:
            return
        if rule["action"] == "alert_only":
            if self.once(("alert", ip, fam), now):
                self.event(now, "alert_only", ip, family=fam, fine=rec.get("fine_label"),
                           reason="politique : alerte sans blocage")
            return
        protos = rule.get("protocols")
        if protos and rec.get("protocol") not in protos:
            if self.once(("proto", ip, fam), now):
                self.event(now, "alert_only", ip, family=fam, fine=rec.get("fine_label"),
                           reason="protocole non bloquable (IP source falsifiable)")
            return
        if (rec.get("family_confidence", 0) < rule["min_confidence"]
                or rec.get("model1_proba_anomal", 0) < rule.get("min_proba", 0)):
            return
        win = self.windows[(ip, fam)]
        win.append(now)
        while win and now - win[0] > rule["window_s"]:
            win.popleft()
        if len(win) >= rule["min_events"]:
            self.block(ip, fam, rec.get("fine_label"), rule, now)

    def block(self, ip, fam, fine, rule, now):
        if len(self.blocked) >= self.policy["max_active_blocks"]:
            if self.once(("breaker",), now, 300):
                self.event(now, "circuit_breaker", ip, family=fam,
                           reason="trop de blocages actifs : blocage automatique suspendu")
            return
        ttl = min(rule["ttl_s"] * 2 ** self.history[ip], self.policy["max_ttl_s"])
        dry = self.policy["mode"] != "enforce" or not self.fw_ok
        if not dry and not self.fw.block(ip, ttl):
            self.event(now, "error", ip, family=fam, reason="echec du blocage nftables")
            return
        self.history[ip] += 1
        self.blocked[ip] = {"since": now, "until": now + ttl, "family": fam,
                            "fine": fine, "dry_run": dry}
        self.windows.pop((ip, fam), None)
        self.event(now, "would_block" if dry else "block", ip, family=fam, fine=fine, ttl_s=ttl,
                   reason=f">= {rule['min_events']} flux {fam} en {rule['window_s']}s")
        self.save()

    def unblock(self, ip, now, reason="manuel"):
        b = self.blocked.pop(ip, None)
        if b is None:
            return False
        if not b["dry_run"]:
            self.fw.unblock(ip)
        self.event(now, "unblock", ip, family=b["family"], reason=reason)
        self.save()
        return True

    def expire(self, now):
        for ip, b in list(self.blocked.items()):
            if b["until"] <= now:
                del self.blocked[ip]       # nftables retire deja l'IP (timeout)
                self.event(now, "expired", ip, family=b["family"])
                self.save()

    def save(self):
        if self.persist:
            write_json(STATE_PATH, {"blocks": self.blocked, "history": dict(self.history)})

    def restore(self):
        """Recharge les blocages reels non expires ; retourne {ip: ttl_restant}."""
        st, now = read_json(STATE_PATH, {}), time.time()
        self.history.update(st.get("history", {}))
        for ip, b in st.get("blocks", {}).items():
            if b["until"] > now and not b["dry_run"]:
                self.blocked[ip] = b
        return {ip: b["until"] - now for ip, b in self.blocked.items()}


# ------------------------------------------------------------------ lecture du journal
def tail(path):
    """Lit les nouvelles lignes ; renvoie None quand rien de neuf (pour les taches de fond)."""
    pos = os.path.getsize(path) if os.path.exists(path) else 0   # on ignore l'historique
    buf = b""
    while True:
        if not os.path.exists(path):
            pos, buf = 0, b""
            yield None
            time.sleep(1)
            continue
        size = os.path.getsize(path)
        if size < pos:                         # fichier tronque / recree
            pos, buf = 0, b""
        if size > pos:
            with open(path, "rb") as f:
                f.seek(pos)
                chunk = f.read(size - pos)
            pos += len(chunk)
            *lines, buf = (buf + chunk).split(b"\n")
            for line in lines:
                yield line.decode("utf-8", "replace").strip()
        else:
            yield None
            time.sleep(1)


def run_daemon():
    os.makedirs(f"{DATA}/config", exist_ok=True)
    if not os.path.exists(POLICY_PATH):
        write_json(POLICY_PATH, DEFAULT_POLICY)
    policy = load_policy()
    fw = NftFirewall()
    eng = Engine(policy, fw, auto_protected())
    fw_ok = fw.setup(eng.restore())
    eng.fw_ok = fw_ok
    if not fw_ok:
        print("[responder] pare-feu indisponible : fonctionnement force en dry-run", flush=True)
    print(f"[responder] mode={policy['mode']}  proteges={sorted(map(str, eng.allow))}", flush=True)

    mtime, last = os.path.getmtime(POLICY_PATH), 0
    for line in tail(LOG_PATH):
        now = time.time()
        if line:
            try:
                eng.handle(json.loads(line), now)
            except (json.JSONDecodeError, TypeError):
                pass
        if now - last >= 2:
            last = now
            if os.path.getmtime(POLICY_PATH) != mtime:
                mtime = os.path.getmtime(POLICY_PATH)
                eng.set_policy(load_policy())
                print(f"[responder] politique rechargee, mode={eng.policy['mode']}", flush=True)
            reqs = read_json(UNBLOCK_PATH, [])
            if reqs:
                for ip in reqs:
                    eng.unblock(str(ip), now)
                write_json(UNBLOCK_PATH, [])
            eng.expire(now)


# ------------------------------------------------------------------ replay (reglage des seuils)
def replay(path):
    policy = load_policy()
    policy["mode"] = "dry-run"
    eng = Engine(policy, NullFirewall(), set(), persist=False)
    total, anomal = 0, Counter()
    with open(path, "rb") as f:
        for raw in f:
            try:
                rec = json.loads(raw)
                ts = datetime.fromisoformat(rec["timestamp"].replace("Z", "+00:00")).timestamp()
            except Exception:
                continue
            total += 1
            if rec.get("verdict") == "anomal":
                anomal[rec.get("family_label")] += 1
            eng.expire(ts)
            eng.handle(rec, ts)
    print(f"Flux lus : {total}   anomalies : {dict(anomal)}")
    print(f"Evenements : {dict(eng.stats)}")
    blocks = [e for e in eng.events if e["event"] == "would_block"]
    print(f"\nBlocages qui AURAIENT eu lieu : {len(blocks)}")
    for e in blocks[:25]:
        print(f"  {e['ts']}  {e['ip']:<16} {e['family']:<12} {e.get('fine') or '':<14} ttl={e['ttl_s']}s")
    alerts = {e["ip"] for e in eng.events if e["event"] == "alert_only"}
    print(f"\nIP signalees SANS blocage (alert_only) : {len(alerts)}  {sorted(alerts)[:10]}")


# ------------------------------------------------------------------ commandes d'administration
def describe_ttl(pol):
    parts = [f"{f} {r['ttl_s']}s" for f, r in pol["rules"].items() if r.get("action") == "block"]
    return ", ".join(parts) + f" (plafond {pol['max_ttl_s']}s)"


def main():
    ap = argparse.ArgumentParser(description="Responder NIDS")
    ap.add_argument("--status", action="store_true", help="mode + blocages actifs")
    ap.add_argument("--set-mode", choices=["off", "dry-run", "enforce"])
    ap.add_argument("--set-profile", choices=sorted(PROFILES),
                    help="duree des blocages : demo (60 s, sans escalade) ou strict (10-15 min, escalade jusqu'a 24 h)")
    ap.add_argument("--unblock", metavar="IP")
    ap.add_argument("--replay", metavar="FICHIER.jsonl",
                    help="rejoue un journal en dry-run pour regler les seuils")
    a = ap.parse_args()
    if a.replay:
        return replay(a.replay)
    if a.set_mode:
        p = read_json(POLICY_PATH, copy.deepcopy(DEFAULT_POLICY))
        p["mode"] = a.set_mode
        write_json(POLICY_PATH, p)
        return print(f"mode -> {a.set_mode} (pris en compte sous ~2 s)")
    if a.set_profile:
        prof = PROFILES[a.set_profile]
        p = read_json(POLICY_PATH, copy.deepcopy(DEFAULT_POLICY))
        p["max_ttl_s"] = prof["max_ttl_s"]
        for fam, ttl in prof["ttl_s"].items():
            p.setdefault("rules", {}).setdefault(fam, copy.deepcopy(DEFAULT_POLICY["rules"][fam]))["ttl_s"] = ttl
        write_json(POLICY_PATH, p)
        return print(f"profil -> {a.set_profile} : {describe_ttl(p)} (pris en compte sous ~2 s)")
    if a.unblock:
        reqs = read_json(UNBLOCK_PATH, [])
        write_json(UNBLOCK_PATH, reqs + [a.unblock])
        return print(f"demande de deblocage envoyee pour {a.unblock}")
    if a.status:
        pol = load_policy()
        print("mode :", pol["mode"])
        print("durees :", describe_ttl(pol))
        blocks = read_json(STATE_PATH, {}).get("blocks", {})
        if not blocks:
            return print("aucun blocage actif")
        for ip, b in blocks.items():
            left = int(b["until"] - time.time())
            print(f"{ip:<16} {b['family']:<12} {'(simule)' if b['dry_run'] else 'ACTIF':<9} reste {max(left, 0)}s")
        return
    run_daemon()


if __name__ == "__main__":
    sys.exit(main())