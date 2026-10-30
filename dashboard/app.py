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
import json
import os
import secrets
import time

import psutil
from flask import (Flask, Response, jsonify, redirect, request,
                    send_from_directory, session, stream_with_context, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__, static_folder="static", static_url_path="/static")
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


@app.route("/api/history")
def history():
    """Les N dernieres detections, pour que le dashboard ne soit pas vide
    a l'ouverture (avant la prochaine detection en direct)."""
    limit = int(request.args.get("limit", "300"))
    if not os.path.exists(LOG_PATH):
        return jsonify([])
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()
    records = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return jsonify(records)


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


@app.route("/api/stream")
def stream():
    """Flux SSE : envoie chaque nouvelle ligne du journal des qu'elle est
    ecrite par le detecteur (un AUTRE processus).

    On ROUVRE le fichier a chaque sondage plutot que de garder un handle
    ouvert en continu : sur Windows en particulier, un handle garde ouvert
    pendant qu'un autre processus ecrit dans le meme fichier peut ne pas
    voir les nouvelles donnees de facon fiable. On travaille en octets
    pour ne consommer que les lignes COMPLETES (pas de JSON tronque si on
    lit pendant une ecriture en cours).
    """

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

            if size > offset:
                with open(LOG_PATH, "rb") as f:
                    f.seek(offset)
                    chunk = f.read()
                last_nl = chunk.rfind(b"\n")
                if last_nl != -1:
                    complete = chunk[:last_nl].decode("utf-8", errors="ignore")
                    offset += last_nl + 1
                    for line in complete.split("\n"):
                        line = line.strip()
                        if line:
                            yield f"data: {line}\n\n"
            else:
                yield ": keep-alive\n\n"

            time.sleep(0.5)

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                     headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def main() -> None:
    global LOG_PATH, MODELS_DIR, CONFIG_DIR, ADMIN_USER, ADMIN_HASH
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

    print(f"[dashboard] journal surveille : {os.path.abspath(LOG_PATH)}")
    print(f"[dashboard] compte admin      : {ADMIN_USER}")
    print(f"[dashboard] ouvre http://{args.host}:{args.port} dans ton navigateur")
    app.run(host=args.host, port=args.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()