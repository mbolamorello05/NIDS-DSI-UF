"""
Detecteur NIDS temps reel -- v6.

A LANCER DEPUIS POWERSHELL EN ADMINISTRATEUR, SUR L'HOTE WINDOWS.

CE QUI CHANGE PAR RAPPORT A v5
    v5 appelait deux modeles entraines sur un dataset public (NF-UQ-NIDS),
    sans les features de fenetre par source, et avec un calcul du debit
    different de celui du dataset d'entrainement (voir le rapport projet
    pour le diagnostic complet). v6 :
      - calcule les features WIN_* EN DIRECT, avec la meme logique causale
        que build_features.py (fenetre de 10s, groupee par IP source) ;
      - charge l'ORDRE DES FEATURES depuis feature_columns.json (ecrit par
        train_models.py) au lieu de le recopier a la main, pour ne jamais
        desynchroniser detection et entrainement ;
      - interroge TROIS modeles : xgb_binary (benign/anormal), puis, si
        anormal, xgb_multiclass_family (scan/ddos/brute_force -- fiable)
        ET xgb_multiclass_fine (type precis -- plus informatif, parfois
        moins fiable sur les classes rares) ;
      - ecrit un journal NDJSON (un objet JSON par ligne), pense pour
        etre relu plus tard par Grafana/Kibana ou un dashboard maison.

UTILISATION
    python realtime_detector_v6.py --models-dir models --log detections_v6.jsonl

PREREQUIS
    pip install nfstream xgboost numpy
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import queue
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone

import numpy as np
import xgboost as xgb
from nfstream import NFStreamer

# ============================================================
# CONFIGURATION -- DOIT RESTER IDENTIQUE A capture_session.py / build_features.py
# ============================================================
IDLE_TIMEOUT = 10
ACTIVE_TIMEOUT = 60
WINDOW_MS = 10_000          # doit rester egal a la fenetre de build_features.py
SOURCE_IDLE_CLEANUP_S = 60  # purge les buffers de sources inactives depuis ce temps
CLEANUP_EVERY_S = 30        # frequence du balayage de nettoyage
HEARTBEAT_S = 10            # point d'etat toutes les N secondes (et non plus tous les N flux)
BATCH_MAX = 512             # nb max de flux classes d'un seul appel au modele
QUEUE_MAX = 100_000         # file d'attente entre la capture et la classification
ALERT_PRINT_S = 1.0         # les alertes sont resumees dans la console 1 fois par seconde

# Doit rester identique a FAMILY dans build_features.py. Sert ici a
# VERIFIER la coherence entre les deux modeles 2, qui sont entraines
# independamment et peuvent donc se contredire (ex. le modele famille dit
# "brute_force" a 47% pendant que le modele fin dit "icmp_flood" a 97% --
# icmp_flood appartient normalement a la famille "ddos", pas
# "brute_force" : c'est un desaccord entre modeles, pas un 4e cas).
FAMILY = {
    "benign": "benign", "port_scan": "scan", "udp_scan": "scan",
    "syn_flood": "ddos", "udp_flood": "ddos", "icmp_flood": "ddos",
    "http_flood": "ddos", "slowloris": "ddos", "brute_force": "brute_force",
}


# ============================================================
# FENETRE GLISSANTE PAR SOURCE (meme algorithme que build_features.py,
# applique en direct flux par flux au lieu d'etre recalcule sur tout le
# dataset)
# ============================================================
class SourceWindow:
    __slots__ = ("buf", "port_c", "ip_c", "proto_c", "small_n", "pkt_sum",
                 "byte_sum", "last_ts")

    def __init__(self) -> None:
        self.buf: deque = deque()  # (ts, dst_port, dst_ip, proto, packets, bytes)
        self.port_c: Counter = Counter()
        self.ip_c: Counter = Counter()
        self.proto_c: Counter = Counter()
        self.small_n = 0
        self.pkt_sum = 0
        self.byte_sum = 0
        self.last_ts = 0

    def push(self, ts: int, dst_port: int, dst_ip: str, proto: int,
              packets: int, nbytes: int) -> dict:
        self.buf.append((ts, dst_port, dst_ip, proto, packets, nbytes))
        self.port_c[dst_port] += 1
        self.ip_c[dst_ip] += 1
        self.proto_c[proto] += 1
        if packets <= 2:
            self.small_n += 1
        self.pkt_sum += packets
        self.byte_sum += nbytes
        self.last_ts = ts

        while self.buf and ts - self.buf[0][0] > WINDOW_MS:
            _, op, oip, oproto, opkt, obyte = self.buf.popleft()
            self.port_c[op] -= 1
            if self.port_c[op] == 0:
                del self.port_c[op]
            self.ip_c[oip] -= 1
            if self.ip_c[oip] == 0:
                del self.ip_c[oip]
            self.proto_c[oproto] -= 1
            if self.proto_c[oproto] == 0:
                del self.proto_c[oproto]
            if opkt <= 2:
                self.small_n -= 1
            self.pkt_sum -= opkt
            self.byte_sum -= obyte

        wsize = len(self.buf)
        span_s = max((ts - self.buf[0][0]) / 1000, 0.001)
        return {
            "WIN_FLOW_COUNT": wsize,
            "WIN_DISTINCT_DST_PORTS": len(self.port_c),
            "WIN_DISTINCT_DST_IPS": len(self.ip_c),
            "WIN_SMALL_FLOW_FRACTION": self.small_n / wsize,
            "WIN_TCP_FRACTION": self.proto_c.get(6, 0) / wsize,
            "WIN_UDP_FRACTION": self.proto_c.get(17, 0) / wsize,
            "WIN_ICMP_FRACTION": self.proto_c.get(1, 0) / wsize,
            "WIN_FLOWS_PER_SEC": wsize / span_s,
            "WIN_PACKETS_SUM": self.pkt_sum,
            "WIN_BYTES_SUM": self.byte_sum,
        }


class SourceWindowStore:
    """Un SourceWindow par IP source, avec purge periodique des sources
    inactives pour ne pas faire grossir la memoire indefiniment sur un
    systeme qui tourne longtemps."""

    def __init__(self) -> None:
        self.by_src: dict[str, SourceWindow] = {}
        self._last_cleanup = time.time()

    def push(self, src_ip: str, *args) -> dict:
        win = self.by_src.setdefault(src_ip, SourceWindow())
        feats = win.push(*args)
        self._maybe_cleanup()
        return feats

    def _maybe_cleanup(self) -> None:
        now = time.time()
        if now - self._last_cleanup < CLEANUP_EVERY_S:
            return
        self._last_cleanup = now
        now_ms = now * 1000
        stale = [ip for ip, w in self.by_src.items()
                  if now_ms - w.last_ts > SOURCE_IDLE_CLEANUP_S * 1000]
        for ip in stale:
            del self.by_src[ip]


# ============================================================
# INTERFACES RESEAU
# ============================================================
def list_interfaces() -> list[dict]:
    """Enumere les interfaces disponibles SUR CETTE MACHINE -- ce code doit
    tourner nativement (jamais dans un conteneur : un conteneur ne voit que
    son propre reseau virtuel, pas les vraies cartes de l'hote).

    Sur Linux/Mac, le nom psutil (ex. "eth0") est directement ce que
    NFStream attend comme `source=`. Sur Windows, NFStream attend le
    chemin Npcap complet ("\\Device\\NPF_{GUID}"), que psutil ne fournit
    pas -- si `scapy` est installe, on s'en sert pour le resoudre a partir
    du nom convivial ; sinon l'interface est quand meme listee, avec un
    avertissement, plutot que d'etre masquee silencieusement.
    """
    import psutil

    win_map: dict[str, str] = {}
    if sys.platform.startswith("win"):
        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                npf = iface.get("name", "")
                if not npf.startswith("\\Device"):
                    guid = iface.get("guid", "")
                    npf = f"\\Device\\NPF_{guid}" if guid else npf
                for key in (iface.get("name", ""), iface.get("description", "")):
                    if key:
                        win_map[key] = npf
        except ImportError:
            pass

    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    results = []
    for name, addr_list in addrs.items():
        st = stats.get(name)
        ips = [a.address for a in addr_list if a.family.name in ("AF_INET", "AF_INET6")]
        on_windows = sys.platform.startswith("win")
        source = win_map.get(name, name) if on_windows else name
        warning = ("chemin Npcap non resolu -- installe 'scapy' (pip install scapy) "
                   "pour une resolution automatique, ou renseigne-le a la main")
        results.append({
            "name": name,
            "source": source,
            "up": bool(st.isup) if st else None,
            "addresses": ips,
            "warning": None if (not on_windows or name in win_map) else warning,
        })
    return results


# ============================================================
# MODELES
# ============================================================
def load_models(models_dir: str):
    with open(os.path.join(models_dir, "feature_columns.json")) as f:
        feature_columns = json.load(f)

    model1 = xgb.XGBClassifier()
    model1.load_model(os.path.join(models_dir, "xgb_binary.json"))

    model2s = {}
    for granularity in ("family", "fine"):
        model_path = os.path.join(models_dir, f"xgb_multiclass_{granularity}.json")
        enc_path = os.path.join(models_dir, f"label_encoder_{granularity}.json")
        if not (os.path.exists(model_path) and os.path.exists(enc_path)):
            continue
        m = xgb.XGBClassifier()
        m.load_model(model_path)
        with open(enc_path) as f:
            enc = json.load(f)
        id_to_label = {v: k for k, v in enc["classes"].items()}
        model2s[granularity] = (m, id_to_label)

    if not model2s:
        print("[ERREUR] aucun modele multiclasse trouve dans", models_dir)
        sys.exit(1)

    return feature_columns, model1, model2s


# ============================================================
# CLASSIFICATION PAR LOTS
# ============================================================
# Pourquoi : appeler predict_proba() sur UN flux a la fois (jusqu'a 3 appels
# par flux anormal) coute ~1 ms d'overhead chacun. Pendant un flood, des
# dizaines de milliers de flux arrivent : le detecteur prenait du retard et
# continuait d'ecrire des alertes bien apres la fin de l'attaque. Ici on
# classe tout ce qui est disponible d'un coup, en un seul appel vectorise.
def classify_batch(items, windows, feature_columns, model1, model2s, threshold):
    """items : liste de (flow, timestamp_iso) dans l'ordre d'arrivee.
    Renvoie la liste des enregistrements (meme format qu'avant, meme ordre)."""
    rows = []
    for flow, _ts in items:
        # La fenetre par source est a etat : on la met a jour flux par flux,
        # dans l'ordre, exactement comme avant.
        win_vals = windows.push(
            flow.src_ip, flow.bidirectional_first_seen_ms, flow.dst_port,
            flow.dst_ip, flow.protocol, flow.bidirectional_packets,
            flow.bidirectional_bytes,
        )
        flow_vals = {
            "SRC_PORT": flow.src_port,
            "DST_PORT": flow.dst_port,
            "PROTOCOL": flow.protocol,
            "BIDIRECTIONAL_PACKETS": flow.bidirectional_packets,
            "BIDIRECTIONAL_BYTES": flow.bidirectional_bytes,
            "BIDIRECTIONAL_DURATION_MS": flow.bidirectional_duration_ms,
            "SRC2DST_PACKETS": flow.src2dst_packets,
            "SRC2DST_BYTES": flow.src2dst_bytes,
            "DST2SRC_PACKETS": flow.dst2src_packets,
            "DST2SRC_BYTES": flow.dst2src_bytes,
        }
        flow_vals.update(win_vals)
        rows.append([flow_vals[c] for c in feature_columns])

    X = np.array(rows, dtype=np.float32)
    p_anomal = model1.predict_proba(X)[:, 1]
    is_anomal = p_anomal >= threshold
    anomal_idx = np.flatnonzero(is_anomal)

    records = []
    for (flow, ts), p, anomal in zip(items, p_anomal, is_anomal):
        records.append({
            "timestamp": ts,
            "src_ip": flow.src_ip, "src_port": flow.src_port,
            "dst_ip": flow.dst_ip, "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "model1_proba_anomal": round(float(p), 4),
            "verdict": "anomal" if anomal else "benign",
        })

    if len(anomal_idx):
        Xa = X[anomal_idx]
        for granularity, (model2, id_to_label) in model2s.items():
            proba = model2.predict_proba(Xa)
            best = np.argmax(proba, axis=1)
            for k, i in enumerate(anomal_idx):
                records[i][f"{granularity}_label"] = id_to_label[int(best[k])]
                records[i][f"{granularity}_confidence"] = round(float(proba[k, best[k]]), 4)
        for i in anomal_idx:
            rec = records[i]
            expected_fam = FAMILY.get(rec.get("fine_label"))
            rec["family_fine_conflict"] = (bool(expected_fam) and "family_label" in rec
                                           and expected_fam != rec["family_label"])
    return records


class AlertPrinter:
    """Console : un resume par seconde et par groupe (source -> cible, type),
    au lieu d'une ligne par flux. Evite de noyer les logs Docker pendant un
    flood (des dizaines de milliers d'ecritures = ralentissement du detecteur)."""

    def __init__(self) -> None:
        self.groups: dict = {}
        self.conflicts = 0
        self.last = time.time()

    def add(self, rec: dict) -> None:
        key = (rec["src_ip"], rec["dst_ip"], rec["dst_port"],
               rec.get("family_label", "?"), rec.get("fine_label", "?"))
        n, conf = self.groups.get(key, (0, 0.0))
        self.groups[key] = (n + 1, conf + rec.get("family_confidence", 0))
        self.conflicts += bool(rec.get("family_fine_conflict"))

    def maybe_flush(self, force: bool = False) -> None:
        now = time.time()
        if not self.groups or (not force and now - self.last < ALERT_PRINT_S):
            return
        self.last = now
        top = sorted(self.groups.items(), key=lambda kv: -kv[1][0])
        for (src, dst, port, fam, fine), (n, conf) in top[:5]:
            print(f"[ALERTE] {src} -> {dst}:{port} | {fam}/{fine} x{n} "
                  f"(conf. moy. {conf / n:.1%})", flush=True)
        if len(top) > 5:
            print(f"[ALERTE] ... et {len(top) - 5} autre(s) groupe(s)", flush=True)
        if self.conflicts:
            print(f"[ALERTE] {self.conflicts} desaccord(s) entre modeles", flush=True)
        self.groups, self.conflicts = {}, 0


_END = object()   # marqueur : la capture s'est terminee


def _reader(streamer, q: "queue.Queue") -> None:
    """Thread de lecture : sort les flux de NFStream et les range dans la file
    des qu'ils sont disponibles, pour que la capture ne soit jamais freinee
    par la classification."""
    try:
        for flow in streamer:
            q.put((flow, datetime.now(timezone.utc).isoformat()))
        q.put(_END)
    except BaseException as exc:          # ex. interface invalide -> remonte au thread principal
        q.put(exc)


# ============================================================
# BOUCLE PRINCIPALE
# ============================================================
def main() -> int:
    ap = argparse.ArgumentParser(description="Detecteur NIDS temps reel (v6)")
    ap.add_argument("--models-dir", default="models")
    ap.add_argument("--interface", default=None,
                     help="interface a capturer (ex. eth0, ou le chemin Npcap complet sur "
                          "Windows). Si omis, lue dans --config (ecrit par le dashboard).")
    ap.add_argument("--list-interfaces", action="store_true",
                     help="liste les interfaces disponibles (JSON), les ecrit dans "
                          "--interfaces-out pour que le dashboard les propose, puis quitte "
                          "sans lancer de capture.")
    ap.add_argument("--interfaces-out", default="config/interfaces.json",
                     help="fichier ecrit par --list-interfaces, lu par le dashboard.")
    ap.add_argument("--config", default="config/detector_config.json",
                     help="fichier ecrit par le dashboard (choix d'interface), lu au "
                          "demarrage si --interface n'est pas donne explicitement.")
    ap.add_argument("--log", default="detections_v6.jsonl")
    ap.add_argument("--threshold", type=float, default=0.5,
                     help="seuil de probabilite du modele 1 pour declarer 'anormal'")
    ap.add_argument("--verbose", action="store_true",
                     help="affiche aussi les flux benign (tres verbeux)")
    args = ap.parse_args()

    if args.list_interfaces:
        ifaces = list_interfaces()
        print(json.dumps(ifaces, indent=2, ensure_ascii=False))
        os.makedirs(os.path.dirname(args.interfaces_out) or ".", exist_ok=True)
        with open(args.interfaces_out, "w", encoding="utf-8") as f:
            json.dump(ifaces, f, indent=2, ensure_ascii=False)
        print(f"\n[OK] {len(ifaces)} interface(s) ecrite(s) dans {args.interfaces_out}")
        print("     Choisis-en une dans le dashboard (Parametres), puis relance ce script.")
        return 0

    interface = args.interface
    if not interface and os.path.exists(args.config):
        with open(args.config, encoding="utf-8") as f:
            interface = json.load(f).get("interface")
    if not interface:
        print("[ERREUR] aucune interface specifiee. Lance d'abord :")
        print(f"  python {os.path.basename(__file__)} --list-interfaces")
        print("puis choisis-en une dans le dashboard (Parametres), ou passe --interface directement.")
        return 1

    feature_columns, model1, model2s = load_models(args.models_dir)
    print("=" * 70)
    print("DETECTEUR NIDS TEMPS REEL -- v6")
    print("=" * 70)
    print(f"Interface        : {interface}")
    print(f"idle_timeout     : {IDLE_TIMEOUT}s | active_timeout : {ACTIVE_TIMEOUT}s")
    print(f"Fenetre WIN_*    : {WINDOW_MS/1000:.0f}s (par IP source)")
    print(f"Seuil modele 1   : {args.threshold}")
    print(f"Granularites     : {list(model2s.keys())}")
    print(f"Journal          : {args.log}")
    print("-" * 70)
    print("En ecoute... (Ctrl+C pour arreter)")
    print("-" * 70)

    windows = SourceWindowStore()
    streamer = NFStreamer(
        source=interface,
        idle_timeout=IDLE_TIMEOUT,
        active_timeout=ACTIVE_TIMEOUT,
        n_meters=1,
    )

    stats = Counter()
    n_flows = 0
    printer = AlertPrinter()
    # buffering=1 => ligne par ligne : chaque detection est ecrite sur le
    # disque des le \n, sans attendre que le tampon se remplisse. Essentiel
    # pour que le dashboard (autre processus) voie les nouvelles lignes
    # rapidement au lieu de les recevoir par rafales.
    log_f = open(args.log, "a", encoding="utf-8", buffering=1)

    q: "queue.Queue" = queue.Queue(maxsize=QUEUE_MAX)
    threading.Thread(target=_reader, args=(streamer, q), daemon=True).start()
    last_beat, beat_flows = time.time(), 0

    try:
        while True:
            try:
                first = q.get(timeout=0.5)
            except queue.Empty:
                printer.maybe_flush()
                continue
            items = [first]
            while len(items) < BATCH_MAX:
                try:
                    items.append(q.get_nowait())
                except queue.Empty:
                    break
            finished = False
            flows = []
            for it in items:
                if isinstance(it, BaseException):
                    raise it
                if it is _END:
                    finished = True
                else:
                    flows.append(it)
            if not flows:
                break
            records = classify_batch(flows, windows, feature_columns, model1,
                                     model2s, args.threshold)

            # une seule ecriture pour tout le lot
            log_f.write("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records))
            n_flows += len(records)
            beat_flows += len(records)
            for r in records:
                if r["verdict"] == "anomal":
                    stats[r.get("family_label", "?")] += 1
                    printer.add(r)
                else:
                    stats["benign"] += 1
                    if args.verbose:
                        print(f"[benign] {r['src_ip']}:{r['src_port']} -> "
                              f"{r['dst_ip']}:{r['dst_port']}")
            printer.maybe_flush()
            if finished:
                break

            now = time.time()
            if now - last_beat >= HEARTBEAT_S:
                print(f"  ... {n_flows} flux traites | {beat_flows / (now - last_beat):.0f} flux/s | "
                      f"file d'attente : {q.qsize()} | {dict(stats)}", flush=True)
                last_beat, beat_flows = now, 0

    except KeyboardInterrupt:
        print("\n[ARRET] demande par l'utilisateur.")
    finally:
        printer.maybe_flush(force=True)
        log_f.close()

    print("-" * 70)
    print(f"[OK] {n_flows} flux traites au total.")
    print(f"     Repartition : {dict(stats)}")
    print(f"     Journal ecrit dans {args.log}")
    return 0


if __name__ == "__main__":
    sys.exit(main())