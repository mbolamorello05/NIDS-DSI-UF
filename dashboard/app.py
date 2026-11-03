r"""
Serveur du dashboard NIDS -- lit detections_v6.jsonl en continu, le diffuse
en direct (SSE), et protege l'acces par un compte admin.

POURQUOI UNE SESSION FLASK PLUTOT QU'UN TOKEN / FLASK-LOGIN
    Usage local, un seul compte admin : une session cote serveur (cookie
    signe par app.secret_key) suffit, pas besoin d'une dependance externe
    ni d'un systeme multi-utilisateurs.

POURQUOI LE MOT DE PASSE EST HACHE EN MEMOIRE, JAMAIS STOCKE EN CLAIR
    Meme pour un usage local, si la machine est partagee ou le process
    inspecte, le mot de passe ne doit pas apparaitre tel quel. On ne garde
    que son hash (werkzeug.security), compare a chaque connexion.

UTILISATION
    pip install flask
    python app.py --log ..\detections_v6.jsonl --admin-password <mot_de_passe> --port 5000
    Puis ouvrir http://localhost:5000 (redirige vers /login si non connecte).
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import secrets
import threading
import time
from collections import deque
from datetime import datetime

import psutil
from flask import (Flask, Response, jsonify, redirect, request,
                    send_from_directory, session, stream_with_context, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.secret_key = secrets.token_hex(32)  # regenere a chaque demarrage -> sessions reinitialisees

LOG_PATH = "detections_v6.jsonl"  # ecrase par --log au demarrage
MODELS_DIR = "models"             # ecrase par --models-dir (pour metrics.json)
CONFIG_DIR = "config"             # ecrase par --config-dir (interfaces.json + detector_config.json)
ADMIN_USER = "admin"              # ecrase par --admin-user
ADMIN_HASH = None                 # calcule au demarrage depuis --admin-password

# Routes accessibles SANS etre connecte. "/static/" est entierement public :
# ce sont du CSS/JS/HTML de presentation (y compris login.html), aucune
# donnee sensible n'y transite -- les vraies donnees passent par /api/*,
# qui restent protegees.
PUBLIC_PREFIXES = ("/login", "/static/")


@app.before_request
def require_login():
    if request.path.startswith(PUBLIC_PREFIXES):
        return None
    if not session.get("logged_in"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "non_authentifie"}), 401
        return redirect(url_for("login"))
    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return send_from_directory(app.static_folder, "login.html")

    data = request.form or request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if username == ADMIN_USER and ADMIN_HASH and check_password_hash(ADMIN_HASH, password):
        session["logged_in"] = True
        session["username"] = username
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Identifiants incorrects"}), 401


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/whoami")
def whoami():
    return jsonify({"username": session.get("username", "?")})


# ============================================================
# AGREGATION DES FLUX
# ============================================================
# Le dashboard n'a pas besoin de chaque flux : il a besoin de savoir QUI
# attaque QUOI, combien de fois et QUAND. Pendant un flood, des dizaines de
# milliers de flux arrivent par seconde ; les envoyer un par un gelait le
# navigateur et noyait l'ecran de lignes identiques. Le journal complet
# (detections_v6.jsonl) reste intact : seul l'affichage est regroupe.
INCIDENT_GAP_S = 10         # au-dela de 10 s sans nouveau flux, le groupe est clos
MAX_SAMPLE_PORTS = 5        # ports de destination cites en exemple
MAX_GROUPS_PER_TICK = 300   # garde-fou : au-dela, on regroupe par source seulement
STREAM_TICK_S = 0.5         # un envoi toutes les 0,5 s : reste "temps reel"
MAX_HISTORY = 5000


def family_of(r: dict) -> str:
    return "benign" if r.get("verdict") == "benign" else (r.get("family_label") or "ddos")


def _group_key(r: dict, coarse: bool = False) -> tuple:
    fam = family_of(r)
    if fam == "benign":
        return (r.get("src_ip", ""), "", "benign", "")
    return (r.get("src_ip", ""), "" if coarse else r.get("dst_ip", ""), fam, r.get("fine_label") or "")


def _new_group(key: tuple, r: dict) -> dict:
    ts = r.get("timestamp", "")
    return {"src_ip": key[0], "dst_ip": key[1], "family": key[2], "fine_label": key[3],
            "count": 0, "ports": [], "n_ports": 0, "first": ts, "last": ts,
            "conf_sum": 0.0, "conflicts": 0, "_ports": set()}


def _add(g: dict, r: dict) -> None:
    g["count"] += 1
    g["last"] = r.get("timestamp", g["last"])
    if g["family"] == "benign":
        return
    g["conf_sum"] += r.get("family_confidence") or 0
    g["conflicts"] += bool(r.get("family_fine_conflict"))
    port = r.get("dst_port")
    if port is not None and port not in g["_ports"]:
        g["_ports"].add(port)
        if len(g["ports"]) < MAX_SAMPLE_PORTS:
            g["ports"].append(port)


def _finish(g: dict) -> dict:
    g["n_ports"] = len(g.pop("_ports"))
    conf_sum = g.pop("conf_sum")
    g["conf"] = round(conf_sum / g["count"], 4) if g["family"] != "benign" and g["count"] else None
    return g


def group_records(records: list, coarse: bool = False) -> list:
    """Regroupe des enregistrements par (source, cible, famille, type).
    Les flux benins sont regroupes par source seulement."""
    groups: dict = {}
    for r in records:
        key = _group_key(r, coarse)
        g = groups.get(key)
        if g is None:
            g = groups[key] = _new_group(key, r)
        _add(g, r)
    return [_finish(g) for g in groups.values()]


def _epoch(ts: str, default: float = 0.0) -> float:
    try:
        return datetime.fromisoformat(ts).timestamp()
    except (ValueError, TypeError):
        return default


def build_incidents(records: list, gap_s: float = INCIDENT_GAP_S) -> list:
    """Comme group_records, mais un groupe est clos des qu'il reste silencieux
    plus de gap_s : une meme source qui attaque a 10 h puis a 14 h donne deux
    incidents distincts. Renvoie les incidents du plus recent au plus ancien."""
    incidents, open_ = [], {}
    last_t = 0.0
    for r in records:
        t = _epoch(r.get("timestamp", ""), last_t)
        last_t = t
        key = _group_key(r)
        g = open_.get(key)
        if g is None or t - g["_t"] > gap_s:
            g = open_[key] = _new_group(key, r)
            incidents.append(g)
        g["_t"] = t
        _add(g, r)
    for g in incidents:
        g.pop("_t", None)
        _finish(g)
    incidents.sort(key=lambda g: g["last"], reverse=True)
    return incidents


class IncidentStore:
    """Registre des incidents, tenu a jour EN CONTINU par un thread qui suit le
    journal (comme le fait le flux SSE). La page Alertes n'a plus a relire et
    re-analyser des dizaines de milliers de lignes : elle lit ce registre, et un
    flood de 100 000 flux apparait en entier (x100 000), pas tronque.

    Memoire bornee : 2000 incidents d'alerte et 500 incidents benins au plus."""

    def __init__(self, path: str, gap_s: float = INCIDENT_GAP_S, bootstrap_bytes: int = 64 * 1024 * 1024,
                 max_alerts: int = 2000, max_benign: int = 500) -> None:
        self.path, self.gap_s, self.bootstrap_bytes = path, gap_s, bootstrap_bytes
        self.alerts: deque = deque(maxlen=max_alerts)
        self.benign: deque = deque(maxlen=max_benign)
        self.open: dict = {}
        self.offset = 0
        self.last_t = 0.0
        self.lock = threading.Lock()

    # -- alimentation ---------------------------------------------------
    def add(self, records: list) -> None:
        with self.lock:
            for r in records:
                t = _epoch(r.get("timestamp", ""), self.last_t)
                self.last_t = t
                key = _group_key(r)
                g = self.open.get(key)
                if g is None or t - g["_t"] > self.gap_s:
                    g = self.open[key] = _new_group(key, r)
                    (self.benign if g["family"] == "benign" else self.alerts).append(g)
                g["_t"] = t
                _add(g, r)
            # les groupes silencieux depuis plus de gap_s sont clos : on les oublie
            if len(self.open) > 1000:
                limit = self.last_t - self.gap_s
                self.open = {k: g for k, g in self.open.items() if g["_t"] >= limit}

    def _read_new(self) -> None:
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return
        if size < self.offset:                 # journal tronque / recree (logrotate)
            self.offset = 0
        if size == self.offset:
            return
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            chunk = f.read(size - self.offset)
        last_nl = chunk.rfind(b"\n")
        if last_nl == -1:
            return                             # ligne encore incomplete
        self.offset += last_nl + 1
        self.add(parse_lines(chunk[:last_nl].split(b"\n")))

    def bootstrap(self) -> None:
        """Au demarrage : reconstruit les incidents recents depuis la fin du journal."""
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return
        self.offset = max(0, size - self.bootstrap_bytes)
        if self.offset:                        # on tombe au milieu d'une ligne : on saute jusqu'au \n suivant
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                skip = f.read(1 << 16).find(b"\n")
            self.offset += skip + 1 if skip != -1 else 0
        while True:                            # lit par tranches de 32 Mo pour borner la memoire
            before = self.offset
            end = min(size, self.offset + 32 * 1024 * 1024)
            with open(self.path, "rb") as f:
                f.seek(before)
                chunk = f.read(end - before)
            last_nl = chunk.rfind(b"\n")
            if last_nl == -1:
                break
            self.offset = before + last_nl + 1
            self.add(parse_lines(chunk[:last_nl].split(b"\n")))
            if self.offset >= size:
                break

    def start(self) -> None:
        def loop() -> None:
            while not os.path.exists(self.path):
                time.sleep(1)
            self.bootstrap()
            while True:
                try:
                    self._read_new()
                except Exception as exc:       # ne jamais tuer le thread
                    print(f"[dashboard] registre d'incidents : {exc}")
                time.sleep(STREAM_TICK_S)
        threading.Thread(target=loop, daemon=True).start()

    # -- lecture --------------------------------------------------------
    def snapshot(self, limit: int = 500) -> list:
        with self.lock:
            out = []
            for g in list(self.alerts) + list(self.benign):
                c = dict(g)
                c.pop("_t", None)
                c["ports"] = list(g["ports"])
                c["n_ports"] = len(c.pop("_ports"))
                conf_sum = c.pop("conf_sum")
                c["conf"] = round(conf_sum / c["count"], 4) if c["family"] != "benign" and c["count"] else None
                out.append(c)
        out.sort(key=lambda x: x["last"], reverse=True)
        return out[:limit]


INCIDENTS: "IncidentStore | None" = None


def tail_lines(path: str, n: int, block: int = 262144) -> list:
    """Les n dernieres lignes SANS relire tout le fichier (le journal grossit
    sans arret : readlines() finissait par saturer la memoire)."""
    chunks, newlines = [], 0
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        while pos > 0 and newlines <= n:
            step = min(block, pos)
            pos -= step
            f.seek(pos)
            part = f.read(step)
            chunks.append(part)
            newlines += part.count(b"\n")
    return b"".join(reversed(chunks)).splitlines()[-n:]


def parse_lines(lines) -> list:
    records = []
    for line in lines:
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="ignore")
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _int_arg(name: str, default: int, maximum: int) -> int:
    try:
        return max(1, min(int(request.args.get(name, default)), maximum))
    except ValueError:
        return default


def _tail_records(n: int) -> list:
    if not os.path.exists(LOG_PATH):
        return []
    return parse_lines(tail_lines(LOG_PATH, n))


@app.route("/api/history")
def history():
    """Les N dernieres detections, flux par flux (export, outils externes)."""
    return jsonify(_tail_records(_int_arg("limit", 300, MAX_HISTORY)))


@app.route("/api/prefill")
def prefill():
    """Etat initial du tableau de bord : les N derniers flux, deja regroupes."""
    return jsonify({"groups": group_records(_tail_records(_int_arg("limit", 300, MAX_HISTORY)))})


@app.route("/api/incidents")
def incidents():
    """Page Alertes : les incidents recents (flux regroupes), pas les flux bruts.
    ?limit = nombre d'incidents renvoyes (500 par defaut)."""
    limit = _int_arg("limit", 500, 2000)
    if INCIDENTS is not None:
        return jsonify(INCIDENTS.snapshot(limit))
    return jsonify(build_incidents(_tail_records(20000))[:limit])   # repli (sans thread de suivi)


# ============================================================
# PREVENTION : le dashboard LIT l'etat ecrit par le responder (blocks.json,
# response_events.jsonl, responder_status.json) et lui DEPOSE des ordres (un
# petit fichier JSON par ordre dans config/commands/). Il ne touche jamais au
# pare-feu lui-meme : le responder reste le seul a avoir NET_ADMIN, et l'admin
# n'a jamais besoin d'ouvrir une console.
# ============================================================
RESPONDER_ALIVE_S = 8        # statut plus vieux que ca = responder arrete
MODES = ("off", "dry-run", "enforce")
PROFILES = ("demo", "strict")


def _data_dir() -> str:
    return os.path.dirname(os.path.abspath(LOG_PATH))


def _read_json_file(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def _tail_events(path: str, n: int) -> list:
    """Les n derniers evenements du responder, du plus recent au plus ancien."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 512 * 1024))      # 512 Ko suffisent pour des centaines d'evenements
            data = f.read()
    except OSError:
        return []
    out = []
    for line in data.splitlines()[-n:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    out.reverse()
    return out


@app.route("/api/prevention")
def prevention():
    now = time.time()
    status = _read_json_file(os.path.join(_data_dir(), "responder_status.json"), None)
    age = (now - status["ts"]) if status and "ts" in status else None
    responder = dict(status or {})
    responder.pop("ts", None)
    responder["alive"] = age is not None and age < RESPONDER_ALIVE_S
    responder["age_s"] = None if age is None else round(age, 1)

    blocks = []
    state = _read_json_file(os.path.join(_data_dir(), "blocks.json"), {})
    for ip, b in (state.get("blocks") or {}).items():
        if b.get("until", 0) <= now:
            continue                                # expire : le responder le purgera
        blocks.append({"ip": ip, "family": b.get("family"), "fine": b.get("fine"),
                       "since": b["since"], "until": b["until"],
                       "duration_s": round(b["until"] - b["since"]),
                       "remaining_s": round(b["until"] - now), "dry_run": bool(b.get("dry_run"))})
    blocks.sort(key=lambda x: x["since"], reverse=True)

    try:
        pending = len([n for n in os.listdir(os.path.join(CONFIG_DIR, "commands")) if n.endswith(".json")])
    except OSError:
        pending = 0
    return jsonify({"now": now, "responder": responder, "blocks": blocks, "pending": pending,
                    "events": _tail_events(os.path.join(_data_dir(), "response_events.jsonl"), 300)})


@app.route("/api/prevention/command", methods=["POST"])
def prevention_command():
    """Depose un ordre pour le responder. Exige un corps JSON (Content-Type
    application/json) : un formulaire venu d'un autre site ne peut pas en envoyer."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "corps JSON attendu"}), 400
    kind, value = data.get("cmd"), data.get("value")
    if kind == "set_mode" and value in MODES:
        payload = {"cmd": kind, "value": value}
    elif kind == "set_profile" and value in PROFILES:
        payload = {"cmd": kind, "value": value}
    elif kind == "unblock":
        try:
            payload = {"cmd": kind, "ip": str(ipaddress.ip_address(str(data.get("ip", "")).strip()))}
        except ValueError:
            return jsonify({"ok": False, "error": "adresse IP invalide"}), 400
    elif kind == "unblock_all":
        payload = {"cmd": kind}
    else:
        return jsonify({"ok": False, "error": "ordre invalide"}), 400

    payload["source"] = "dashboard"
    cmd_dir = os.path.join(CONFIG_DIR, "commands")
    os.makedirs(cmd_dir, exist_ok=True)
    final = os.path.join(cmd_dir, f"{time.time_ns()}-{secrets.token_hex(3)}.json")
    tmp = os.path.join(cmd_dir, "." + os.path.basename(final)[:-5] + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:     # ecriture atomique : le responder ne lit jamais un ordre a moitie ecrit
        json.dump(payload, f, ensure_ascii=False)
    os.replace(tmp, final)
    return jsonify({"ok": True})


@app.route("/api/system")
def system_stats():
    """Charge reelle de la machine qui fait tourner le dashboard (CPU,
    RAM, disque) -- via psutil, pas des valeurs decoratives."""
    return jsonify({
        "cpu": psutil.cpu_percent(interval=0.2),
        "memory": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage(os.path.abspath(os.sep)).percent,
    })


@app.route("/api/config")
def config_info():
    """Ce que le dashboard sait reellement de sa propre configuration --
    pour la page Parametres (pas de valeurs inventees)."""
    return jsonify({
        "log_path": os.path.abspath(LOG_PATH),
        "models_dir": os.path.abspath(MODELS_DIR),
        "admin_user": ADMIN_USER,
    })


@app.route("/api/interfaces", methods=["GET", "POST"])
def interfaces():
    """GET : liste des interfaces reseau disponibles, telle qu'ecrite par
    `realtime_detector_v6.py --list-interfaces` (ce dashboard, en
    conteneur, ne peut PAS les detecter lui-meme -- il ne voit jamais les
    vraies cartes reseau de l'hote, voir la note dans le detecteur).
    POST : enregistre le choix de l'admin pour le PROCHAIN demarrage du
    detecteur (pas un changement a chaud -- NFStream se lie a une
    interface au demarrage de la capture)."""
    iface_path = os.path.join(CONFIG_DIR, "interfaces.json")
    config_path = os.path.join(CONFIG_DIR, "detector_config.json")

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        chosen = data.get("interface")
        if not chosen:
            return jsonify({"ok": False, "error": "interface manquante"}), 400
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump({"interface": chosen}, f, indent=2, ensure_ascii=False)
        return jsonify({"ok": True})

    if not os.path.exists(iface_path):
        return jsonify({"error": "interfaces_introuvables",
                         "message": "Lance d'abord, nativement sur l'hote : "
                                    "python realtime_detector_v6.py --list-interfaces"}), 404
    with open(iface_path, "r", encoding="utf-8") as f:
        available = json.load(f)
    current = None
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            current = json.load(f).get("interface")
    return jsonify({"available": available, "current": current})


@app.route("/api/metrics")
def metrics():
    """Metriques du dernier entrainement (ecrites par train_models.py dans
    models/metrics.json) : rien n'est recalcule ici, on sert tel quel ce
    que l'entrainement a reellement mesure."""
    path = os.path.join(MODELS_DIR, "metrics.json")
    if not os.path.exists(path):
        return jsonify({"error": "metrics_introuvable",
                         "message": f"{path} n'existe pas -- lance train_models.py d'abord."}), 404
    with open(path, "r", encoding="utf-8") as f:
        return jsonify(json.load(f))


def aggregate_tick(lines) -> dict | None:
    """Transforme les nouvelles lignes du journal en UN message regroupe."""
    records = parse_lines(lines)
    if not records:
        return None
    groups = group_records(records)
    if len(groups) > MAX_GROUPS_PER_TICK:      # ex. scan sur des milliers de cibles
        groups = group_records(records, coarse=True)
    return {"n": len(records), "groups": groups}


@app.route("/api/stream")
def stream():
    """Flux SSE : toutes les 0,5 s, UN message qui resume les flux detectes
    depuis le precedent (compteurs exacts, mais regroupes par source/cible/
    type). Le detecteur est un AUTRE processus : on rouvre le fichier a chaque
    sondage plutot que de garder un handle ouvert (fiable meme si un autre
    processus ecrit dedans), et on travaille en octets pour ne consommer que
    les lignes COMPLETES (jamais de JSON tronque)."""

    def generate():
        while not os.path.exists(LOG_PATH):
            time.sleep(1)
        offset = os.path.getsize(LOG_PATH)

        while True:
            try:
                size = os.path.getsize(LOG_PATH)
            except OSError:
                time.sleep(0.5)
                continue

            if size < offset:
                offset = 0  # fichier recree/tronque -> on repart de zero

            msg = None
            if size > offset:
                with open(LOG_PATH, "rb") as f:
                    f.seek(offset)
                    chunk = f.read()
                last_nl = chunk.rfind(b"\n")
                if last_nl != -1:
                    offset += last_nl + 1
                    msg = aggregate_tick(chunk[:last_nl].split(b"\n"))

            if msg:
                yield f"data: {json.dumps(msg, separators=(',', ':'))}\n\n"
            else:
                yield ": keep-alive\n\n"

            time.sleep(STREAM_TICK_S)

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                     headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def main() -> None:
    global LOG_PATH, MODELS_DIR, CONFIG_DIR, ADMIN_USER, ADMIN_HASH, INCIDENTS
    ap = argparse.ArgumentParser(description="Dashboard NIDS temps reel")
    ap.add_argument("--log", default="detections_v6.jsonl",
                     help="chemin vers le journal ecrit par realtime_detector_v6.py")
    ap.add_argument("--models-dir", default="models",
                     help="dossier contenant metrics.json (ecrit par train_models.py)")
    ap.add_argument("--config-dir", default="config",
                     help="dossier PARTAGE EN LECTURE/ECRITURE avec le detecteur -- "
                          "interfaces.json (liste) et detector_config.json (choix admin)")
    ap.add_argument("--admin-user", default="admin")
    ap.add_argument("--admin-password", default=None,
                     help="si omis, demande de le saisir au demarrage (recommande : "
                          "ne jamais le passer en clair dans un historique de commandes)")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    LOG_PATH = args.log
    MODELS_DIR = args.models_dir
    CONFIG_DIR = args.config_dir
    ADMIN_USER = args.admin_user
    password = args.admin_password or getpass.getpass("Mot de passe admin du dashboard : ")
    ADMIN_HASH = generate_password_hash(password)

    INCIDENTS = IncidentStore(LOG_PATH)
    INCIDENTS.start()
    print(f"[dashboard] journal surveille : {os.path.abspath(LOG_PATH)}")
    print(f"[dashboard] compte admin      : {ADMIN_USER}")
    print(f"[dashboard] ouvre http://{args.host}:{args.port} dans ton navigateur")
    app.run(host=args.host, port=args.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()