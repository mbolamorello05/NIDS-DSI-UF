"""
Nettoyage du dataset NIDS (captures NFStream -> un .parquet par scénario).

POURQUOI
    Chaque fichier est étiqueté EN BLOC avec le nom du scénario ("port_scan", ...).
    Mais la capture démarre avant l'attaque et continue pendant : le trafic de fond
    (DNS, Internet, mDNS, ...) se retrouve étiqueté "attaque" à tort. Inversement,
    un fichier "benign" peut contenir une attaque lancée par erreur.

PRINCIPE
    On ne fait pas confiance à l'étiquette du fichier : on la VÉRIFIE flux par flux.
    1. Signature "coeur" : ce qui est SÛREMENT l'attaque (qui -> qui, protocole, port).
    2. Fenêtre d'attaque : de la 1re à la dernière occurrence du coeur (+ marge).
    3. Chaque flux reçoit une décision :
         - keep            : reste dans le dataset avec son label
         - relabel_benign  : trafic de fond réel -> devient "benign"
         - quarantine      : ambigu -> sorti du dataset, écrit dans quarantine.parquet
    Rien n'est supprimé en silence : chaque flux garde LABEL_ORIGINAL + CLEAN_REASON.

    On RELABELLISE le fond en "benign" (au lieu de le jeter) car c'est du vrai trafic
    normal, et car les features par fenêtre (ports distincts par source, etc.) auront
    besoin de TOUT le trafic de la capture pour être calculées correctement.

UTILISATION
    python clean_dataset.py --input-dir Dataset --output-dir Dataset_clean
"""

from __future__ import annotations

import argparse
import glob
import os
import sys
from collections import Counter

import polars as pl

# ============================================================
# CONFIGURATION (à adapter si ton lab change)
# ============================================================
HOST = "192.168.148.1"                      # hôte Windows
KALIS = ["192.168.148.139", "192.168.148.135"]  # tes deux VM Kali
LAB = KALIS + [HOST]

TS = "BIDIRECTIONAL_FIRST_SEEN_MS"
TE = "BIDIRECTIONAL_LAST_SEEN_MS"

WINDOW_MARGIN_MS = 3_000      # marge autour de la fenêtre d'attaque
CLUSTER_GAP_MS = 5_000        # deux flux coeur espacés de moins que ça = même rafale
STRAY_GAP_MS = 120_000        # rafale isolée à plus de 2 min des autres = suspecte
STRAY_MAX_FRACTION = 0.01     # ... et contenant < 1 % des flux coeur

SCAN_MIN_PORTS = 10           # détection de scan caché dans un fichier benign :
SCAN_WINDOW_MS = 10_000       # >= 10 ports distincts vers la même IP en 10 s

REQUIRED_COLUMNS = [
    "SRC_IP", "DST_IP", "PROTOCOL", "DST_PORT", "SRC2DST_PACKETS",
    "BIDIRECTIONAL_PACKETS", TS, TE, "LABEL",
]


def _kali_to_host() -> pl.Expr:
    return pl.col("SRC_IP").is_in(KALIS) & (pl.col("DST_IP") == HOST)


def _lab_to_lab() -> pl.Expr:
    return pl.col("SRC_IP").is_in(LAB) & pl.col("DST_IP").is_in(LAB)


# Signature "coeur" de chaque scénario = flux SÛREMENT issus de l'attaque.
#   proto            : numéro de protocole IP
#   core             : expression Polars de la signature
#   absorb_same_proto: les flux lab->lab du même protocole DANS la fenêtre sont
#                      aussi l'attaque (ICMP : flux de queue/rampe d'un flood découpé)
SCENARIOS = {
    "port_scan": dict(
        proto=6, absorb_same_proto=False,
        core=lambda: _kali_to_host() & (pl.col("SRC2DST_PACKETS") <= 3),
    ),
    "udp_scan": dict(
        proto=17, absorb_same_proto=False,
        core=lambda: _kali_to_host(),
    ),
    "syn_flood": dict(
        proto=6, absorb_same_proto=False,
        core=lambda: _kali_to_host() & (pl.col("DST_PORT") == 80),
    ),
    "udp_flood": dict(
        proto=17, absorb_same_proto=False,
        core=lambda: _kali_to_host() & (pl.col("DST_PORT") == 53),
    ),
    # Port 22 = SSH (hydra). Elargi pour couvrir aussi FTP (21), SMB (445)
    # et RDP (3389) -- memes acteurs/forme de flux, juste un autre service
    # cible. Toujours etiquete "brute_force" : on diversifie la classe
    # plutot que d'en creer une nouvelle (voir Palier 1).
    "brute_force": dict(
        proto=6, absorb_same_proto=False,
        core=lambda: _kali_to_host() & pl.col("DST_PORT").is_in([21, 22, 445, 3389]),
    ),
    # ICMP : les deux Kali et l'hôte s'attaquent entre eux -> n'importe quelle paire du lab
    "icmp_flood": dict(
        proto=1, absorb_same_proto=True,
        core=lambda: _lab_to_lab() & (pl.col("BIDIRECTIONAL_PACKETS") >= 100),
    ),
    # Flood HTTP (ab) : meme forme que syn_flood (Kali -> hôte, port 80),
    # distingue uniquement par le fichier source, pas par la signature.
    "http_flood": dict(
        proto=6, absorb_same_proto=False,
        core=lambda: _kali_to_host() & (pl.col("DST_PORT") == 80),
    ),
    # Slowloris : memes acteurs/port que http_flood et syn_flood, mais
    # peu de paquets par flux et connexions tres longues (proches de
    # ACTIVE_TIMEOUT du capteur) -- la signature reste large ici, c'est
    # aux features WIN_* (calculees ensuite) de capturer ce qui la rend
    # different d'un flood classique.
    "slowloris": dict(
        proto=6, absorb_same_proto=False,
        core=lambda: _kali_to_host() & (pl.col("DST_PORT") == 80),
    ),
}

# Raisons -> décision
ATTACK_REASONS = ["core_signature", "same_protocol_lab_flow_in_window"]
BENIGN_REASONS = ["background_traffic", "lab_flow_outside_attack_window", "benign_file"]
# tout le reste = quarantine :
#   stray_core_flow_outside_attack_window, lab_flow_not_matching_signature,
#   no_core_flow_in_file, scan_like_burst_in_benign_file


# ============================================================
# OUTILS
# ============================================================
def scenario_of(path: str) -> str:
    """Retrouve le scenario a partir du nom de fichier, quel que soit le
    format de l'horodatage ajoute derriere (2 segments dans les fichiers
    de capture_session.py, 3 dans l'ancien dataset) : on compare au prefixe
    le plus long parmi les noms de scenario connus, plutot que de compter
    les underscores.
        'port_scan_20261019_143928.parquet'        -> 'port_scan'
        'port_scan_20261018_163424_177139.parquet'  -> 'port_scan'
    """
    stem = os.path.splitext(os.path.basename(path))[0]
    known = sorted(["benign", *SCENARIOS.keys()], key=len, reverse=True)
    for label in known:
        if stem == label or stem.startswith(label + "_"):
            return label
    return stem.rsplit("_", 3)[0]  # repli si rien ne correspond


def merge_clusters(starts: list[int], ends: list[int], gap: int) -> list[dict]:
    """Regroupe les flux en rafales : on chaîne les intervalles [début, fin]
    dont l'écart est <= gap (gère aussi les flux longs de 30 s)."""
    order = sorted(range(len(starts)), key=lambda i: starts[i])
    clusters: list[dict] = []
    for i in order:
        if clusters and starts[i] - clusters[-1]["end"] <= gap:
            c = clusters[-1]
            c["end"] = max(c["end"], ends[i])
            c["idx"].append(i)
        else:
            clusters.append({"start": starts[i], "end": ends[i], "idx": [i]})
    return clusters


def stray_positions(clusters: list[dict], total: int) -> list[int]:
    """Positions (dans la liste des flux coeur) des rafales isolées et minuscules."""
    if len(clusters) < 2:
        return []
    stray: list[int] = []
    for k, c in enumerate(clusters):
        dist = min(
            max(c["start"] - o["end"], o["start"] - c["end"], 0)
            for j, o in enumerate(clusters) if j != k
        )
        if dist > STRAY_GAP_MS and len(c["idx"]) < max(3, STRAY_MAX_FRACTION * total):
            stray += c["idx"]
    return stray


def scan_like_rows(df: pl.DataFrame) -> set[int]:
    """Indices des flux appartenant à une rafale de type scan de ports
    (>= SCAN_MIN_PORTS ports distincts, même src->dst, en SCAN_WINDOW_MS)."""
    flagged: set[int] = set()
    t = df.filter(pl.col("PROTOCOL").is_in([6, 17])).select(
        ["_i", "SRC_IP", "DST_IP", "PROTOCOL", "DST_PORT", TS]
    )
    for _, g in t.group_by(["SRC_IP", "DST_IP", "PROTOCOL"]):
        if g["DST_PORT"].n_unique() < SCAN_MIN_PORTS:
            continue
        g = g.sort(TS)
        rows, ts, ports = g["_i"].to_list(), g[TS].to_list(), g["DST_PORT"].to_list()
        window: Counter = Counter()
        lo = 0
        for hi in range(len(ts)):
            window[ports[hi]] += 1
            while ts[hi] - ts[lo] > SCAN_WINDOW_MS:
                window[ports[lo]] -= 1
                if window[ports[lo]] == 0:
                    del window[ports[lo]]
                lo += 1
            if len(window) >= SCAN_MIN_PORTS:
                flagged.update(rows[lo:hi + 1])
    return flagged


# ============================================================
# NETTOYAGE D'UN FICHIER
# ============================================================
def clean_attack_file(df: pl.DataFrame, scenario: str) -> pl.DataFrame:
    cfg = SCENARIOS[scenario]
    core_expr = (pl.col("PROTOCOL") == cfg["proto"]) & cfg["core"]()
    df = df.with_columns(core_expr.alias("_core"))
    core = df.filter(pl.col("_core"))

    if core.height == 0:
        return df.with_columns(pl.lit("no_core_flow_in_file").alias("CLEAN_REASON"))

    # 1) rafales coeur isolées (flux qui ressemblent à l'attaque mais loin des autres)
    clusters = merge_clusters(core[TS].to_list(), core[TE].to_list(), CLUSTER_GAP_MS)
    stray_pos = stray_positions(clusters, core.height)
    stray_ids = core["_i"].gather(stray_pos).to_list() if stray_pos else []
    df = df.with_columns(pl.col("_i").is_in(stray_ids).alias("_stray"))

    # 2) fenêtre d'attaque (sans les isolés)
    good = df.filter(pl.col("_core") & ~pl.col("_stray"))
    w0 = good[TS].min() - WINDOW_MARGIN_MS
    w1 = good[TE].max() + WINDOW_MARGIN_MS
    in_window = (pl.col(TS) >= w0) & (pl.col(TS) <= w1)
    same_proto = pl.col("PROTOCOL") == cfg["proto"]

    # 3) décision, par ordre de priorité
    reason = (
        pl.when(pl.col("_stray")).then(pl.lit("stray_core_flow_outside_attack_window"))
        .when(pl.col("_core")).then(pl.lit("core_signature"))
        .when(_lab_to_lab() & in_window & same_proto & pl.lit(cfg["absorb_same_proto"]))
        .then(pl.lit("same_protocol_lab_flow_in_window"))
        .when(_lab_to_lab() & in_window).then(pl.lit("lab_flow_not_matching_signature"))
        .when(_lab_to_lab()).then(pl.lit("lab_flow_outside_attack_window"))
        .otherwise(pl.lit("background_traffic"))
    )
    return df.with_columns(reason.alias("CLEAN_REASON"))


def clean_benign_file(df: pl.DataFrame) -> pl.DataFrame:
    flagged = list(scan_like_rows(df))
    reason = (
        pl.when(pl.col("_i").is_in(flagged)).then(pl.lit("scan_like_burst_in_benign_file"))
        .otherwise(pl.lit("benign_file"))
    )
    return df.with_columns(reason.alias("CLEAN_REASON"))


def finalize(df: pl.DataFrame, scenario: str, source: str) -> pl.DataFrame:
    """Ajoute LABEL (nettoyé), LABEL_ORIGINAL, CLEAN_ACTION, SOURCE_FILE."""
    r = pl.col("CLEAN_REASON")
    action = (
        pl.when(r.is_in(ATTACK_REASONS)).then(pl.lit("keep"))
        .when(r.is_in(BENIGN_REASONS)).then(
            pl.lit("keep") if scenario == "benign" else pl.lit("relabel_benign"))
        .otherwise(pl.lit("quarantine"))
    )
    label = (
        pl.when(r.is_in(ATTACK_REASONS)).then(pl.lit(scenario))
        .when(r.is_in(BENIGN_REASONS)).then(pl.lit("benign"))
        .otherwise(pl.col("LABEL"))  # quarantaine : on garde l'étiquette d'origine
    )
    drop_tmp = [c for c in ("_i", "_core", "_stray") if c in df.columns]
    return (
        df.with_columns(
            pl.col("LABEL").alias("LABEL_ORIGINAL"),
            action.alias("CLEAN_ACTION"),
            label.alias("LABEL_CLEAN"),
            pl.lit(source).alias("SOURCE_FILE"),
        )
        .drop(drop_tmp + ["LABEL"])
        .rename({"LABEL_CLEAN": "LABEL"})
    )


# ============================================================
# PROGRAMME PRINCIPAL
# ============================================================
def main() -> int:
    ap = argparse.ArgumentParser(description="Nettoyage du dataset NIDS")
    ap.add_argument("--input-dir", default="Dataset")
    ap.add_argument("--output-dir", default="Dataset_clean")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.input_dir, "*.parquet")))
    if not files:
        print(f"[ERREUR] aucun .parquet dans {args.input_dir}")
        return 1
    os.makedirs(args.output_dir, exist_ok=True)

    parts: list[pl.DataFrame] = []
    for path in files:
        name = os.path.basename(path)
        scenario = scenario_of(path)
        if scenario != "benign" and scenario not in SCENARIOS:
            print(f"[IGNORÉ] {name} : scénario inconnu '{scenario}' (ajoute-le dans SCENARIOS)")
            continue
        df = pl.read_parquet(path)
        missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
        if missing:
            print(f"[IGNORÉ] {name} : colonnes manquantes {missing}")
            continue
        df = df.with_row_index("_i")
        df = clean_benign_file(df) if scenario == "benign" else clean_attack_file(df, scenario)
        parts.append(finalize(df, scenario, name))

    # "diagonal_relaxed" aligne les colonnes PAR NOM (et complete par null
    # si l'une manque), contrairement a "vertical_relaxed" qui empile par
    # POSITION : indispensable ici car les anciennes captures ont les
    # colonnes triees alphabetiquement, et capture_session.py les ecrit
    # dans l'ordre natif de NFStream.
    full = pl.concat(parts, how="diagonal_relaxed")
    clean = full.filter(pl.col("CLEAN_ACTION") != "quarantine")
    quarantine = full.filter(pl.col("CLEAN_ACTION") == "quarantine")

    clean.write_parquet(os.path.join(args.output_dir, "dataset_clean.parquet"))
    quarantine.write_parquet(os.path.join(args.output_dir, "quarantine.parquet"))

    report = (
        full.group_by(["SOURCE_FILE", "LABEL_ORIGINAL", "CLEAN_ACTION", "CLEAN_REASON", "LABEL"])
        .agg(pl.len().alias("n_flux"))
        .sort(["SOURCE_FILE", "n_flux"], descending=[False, True])
    )
    report.write_csv(os.path.join(args.output_dir, "cleaning_report.csv"))

    # ---------- résumé console ----------
    print("\n" + "=" * 78)
    print("RÉSUMÉ DU NETTOYAGE")
    print("=" * 78)
    per_file = (
        full.group_by("SOURCE_FILE", maintain_order=True)
        .agg(
            pl.len().alias("total"),
            (pl.col("CLEAN_REASON").is_in(ATTACK_REASONS)).sum().alias("attaque"),
            (pl.col("CLEAN_ACTION") == "relabel_benign").sum().alias("->benign"),
            (pl.col("CLEAN_ACTION") == "quarantine").sum().alias("quarantaine"),
        )
    )
    with pl.Config(tbl_rows=60, tbl_width_chars=140, fmt_str_lengths=60):
        print(per_file)
        print("\nRépartition AVANT (étiquette du fichier) :")
        print(full.group_by("LABEL_ORIGINAL").len().sort("len", descending=True))
        print("\nRépartition APRÈS nettoyage :")
        print(clean.group_by("LABEL").len().sort("len", descending=True))
        if quarantine.height:
            print("\nFlux en quarantaine (à vérifier à la main) :")
            print(quarantine.group_by(["SOURCE_FILE", "CLEAN_REASON"]).len().sort("SOURCE_FILE"))

    assert clean.height + quarantine.height == full.height, "des flux ont disparu !"
    print(f"\n[OK] {clean.height:,} flux conservés | {quarantine.height:,} en quarantaine "
          f"| total {full.height:,}")
    print(f"[OK] Fichiers écrits dans : {args.output_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())