"""
Capture d'une session de trafic pour construire le dataset NIDS.

A LANCER DEPUIS POWERSHELL EN ADMINISTRATEUR, SUR L'HOTE WINDOWS.

PRINCIPE
    Une capture = un scenario = un fichier .parquet, etiquete EN BLOC avec
    --label (comme avant). clean_dataset.py se charge ensuite de corriger
    les flux mal etiquetes (bruit avant/apres l'attaque).

POURQUOI idle_timeout=10 / active_timeout=60 FIXES EN DUR
    Ce sont EXACTEMENT les valeurs utilisees par realtime_detector_v5.py.
    Un flux capture ici doit avoir la meme duree de vie qu'un flux vu en
    detection temps reel, sinon le modele apprend des artefacts de capture
    au lieu du comportement de l'attaque (c'est ce qui s'est passe sur tes
    fichiers icmp_flood precedents : 30s de timeout sur certains, 1s sur
    d'autres). Si tu changes ces valeurs, change-les aussi dans le
    detecteur, et recapture tout.

EXEMPLE
    python capture_session.py --label syn_flood --duration 30 ^
        --output-dir nids_dataset_v2\raw

    1. Lance la commande ci-dessus.
    2. Des que "Capture en cours..." s'affiche, lance l'attaque depuis
       Kali (voir attack_launcher.sh) avec la MEME duree (ou un peu moins).
    3. Laisse le script s'arreter tout seul (ne fais pas Ctrl+C avant,
       sinon les derniers flux actifs seront perdus).

PREREQUIS
    pip install nfstream pandas pyarrow
"""

import argparse
import os
import sys
import time
from datetime import datetime

import pandas as pd
from nfstream import NFStreamer

# ============================================================
# CONFIGURATION (ne pas changer sans changer aussi le detecteur)
# ============================================================
INTERFACE_DEFAULT = r"\Device\NPF_{7AD1E2BA-F912-41D3-A09D-DB7ABCEDB9BB}"
IDLE_TIMEOUT = 10      # secondes sans paquet -> le flux expire et est exporte
ACTIVE_TIMEOUT = 60    # duree max d'un flux avant export force
STOP_MARGIN = 5        # marge supplementaire apres idle_timeout avant l'arret dur

VALID_LABELS = [
    "benign", "port_scan", "udp_scan", "syn_flood",
    "udp_flood", "icmp_flood", "brute_force",
    "http_flood", "slowloris",
]

PROGRESS_EVERY_S = 10  # affichage d'un point d'etat toutes les N secondes


def capture(interface: str, total_stop_s: float) -> list:
    """Itere sur les flux NFStream et s'arrete au bout de total_stop_s.

    On ne peut pas utiliser NFStreamer(...).to_pandas() ici : en capture
    live, cet appel ne rend la main qu'a l'arret manuel (Ctrl+C). On lit
    donc les flux un par un (comme le fait realtime_detector_v5.py) et on
    sort de la boucle nous-memes une fois le temps ecoule.
    """
    streamer = NFStreamer(
        source=interface,
        idle_timeout=IDLE_TIMEOUT,
        active_timeout=ACTIVE_TIMEOUT,
        n_meters=1,
    )

    rows = []
    columns = None
    start = time.time()
    last_print = start

    try:
        for flow in streamer:
            if columns is None:
                columns = flow.keys()
            rows.append(flow.values())

            now = time.time()
            if now - last_print >= PROGRESS_EVERY_S:
                print(f"  [{now - start:5.0f}s] {len(rows)} flux captures")
                last_print = now
            if now >= start + total_stop_s:
                break
    except KeyboardInterrupt:
        print("\n[ARRET MANUEL] les flux encore actifs a cet instant sont perdus.")

    if not rows:
        return [], None
    return rows, columns


def main() -> int:
    ap = argparse.ArgumentParser(description="Capture une session de trafic pour le dataset NIDS")
    ap.add_argument("--label", required=True, choices=VALID_LABELS)
    ap.add_argument("--duration", type=int, required=True,
                     help="duree de capture en secondes (duree de l'attaque / du trafic a capturer)")
    ap.add_argument("--interface", default=INTERFACE_DEFAULT)
    ap.add_argument("--output-dir", default="nids_dataset_v2/raw")
    args = ap.parse_args()

    if args.duration <= 0:
        print("[ERREUR] --duration doit etre > 0")
        return 1

    os.makedirs(args.output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output_dir, f"{args.label}_{ts}.parquet")

    hard_stop = args.duration + IDLE_TIMEOUT + STOP_MARGIN

    print("=" * 60)
    print(f"CAPTURE : {args.label}")
    print("=" * 60)
    print(f"Interface        : {args.interface}")
    print(f"Duree demandee   : {args.duration}s")
    print(f"idle_timeout     : {IDLE_TIMEOUT}s")
    print(f"active_timeout   : {ACTIVE_TIMEOUT}s")
    print(f"Arret automatique dans {hard_stop}s (marge pour vider les derniers flux)")
    print(f"Sortie           : {out_path}")
    print("-" * 60)
    print("Capture en cours... lance ton attaque / ton trafic maintenant.")
    print("-" * 60)

    rows, columns = capture(args.interface, hard_stop)

    if not rows:
        print("[ERREUR] aucun flux capture (verifie l'interface et les droits administrateur).")
        return 1

    df = pd.DataFrame(rows, columns=columns)
    df.columns = [c.upper() for c in df.columns]
    df["LABEL"] = args.label

    df.to_parquet(out_path, index=False)

    print("-" * 60)
    print(f"[OK] {len(df)} flux ecrits dans {out_path}")
    if "BIDIRECTIONAL_FIRST_SEEN_MS" in df.columns:
        span_s = (df["BIDIRECTIONAL_LAST_SEEN_MS"].max() - df["BIDIRECTIONAL_FIRST_SEEN_MS"].min()) / 1000
        print(f"      duree reelle couverte : {span_s:.1f}s")
    print("\nProchaine etape : relance clean_dataset.py avec --input-dir pointant")
    print(f"vers {args.output_dir} une fois toutes les sessions capturees.")
    return 0


if __name__ == "__main__":
    sys.exit(main())