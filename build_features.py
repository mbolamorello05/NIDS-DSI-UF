"""
Construit le dataset final d'entrainement a partir du dataset nettoye
(clean_dataset.py) : ajoute des features PAR SOURCE sur fenetre glissante
en plus des features existantes PAR FLUX.

POURQUOI CES FEATURES
    Un flux seul ne suffit pas a distinguer un scan ou un flood d'un flux
    normal (on l'a verifie : un SYN scan et une connexion TCP vers un port
    ferme sont quasi identiques flux par flux). Ce qui les distingue, c'est
    le COMPORTEMENT DE LA SOURCE dans le temps : combien de ports touches,
    combien de flux par seconde, etc.

COMMENT (choix documentes, voir echange avec Claude) :
    - Regroupement : par IP SOURCE seule (pas par paire source/destination)
      -> un scan touche une seule destination avec plein de ports : grouper
         par paire diluerait justement le signal qu'on cherche a capturer,
         et une seule structure par source est aussi plus simple a tenir
         a jour en temps reel (voir realtime_detector_v6).
    - Fenetre : 10 secondes, alignee sur IDLE_TIMEOUT (meme valeur que
      capture_session.py / realtime_detector_v5.py) pour eviter tout
      nouveau biais entrainement/detection.
    - Fenetre CAUSALE : pour chaque flux, on ne regarde que les flux de la
      meme source AVANT ou AU MEME INSTANT (jamais apres). C'est obligatoire :
      en detection reelle, on ne connait pas le futur au moment de decider.

SORTIE
    Chaque flux garde ses features par flux + recoit les features
    WIN_* calculees sur les 10 dernieres secondes de SA source, plus deux
    colonnes de label :
      - LABEL         : le label fin (port_scan, udp_scan, syn_flood, ...)
      - LABEL_FAMILY  : la famille (scan, ddos, brute_force, benign)

UTILISATION
    python build_features.py --input clean/dataset_clean.parquet --output features/dataset_features.parquet
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter

import polars as pl

TS = "BIDIRECTIONAL_FIRST_SEEN_MS"
WINDOW_MS = 10_000  # 10s -- doit rester identique a IDLE_TIMEOUT du capteur

FAMILY = {
    "benign": "benign",
    "port_scan": "scan",
    "udp_scan": "scan",
    "syn_flood": "ddos",
    "udp_flood": "ddos",
    "icmp_flood": "ddos",
    "http_flood": "ddos",   # DDoS applicatif (L7) -- meme famille, mecanisme different
    "slowloris": "ddos",    # DoS lent -- regroupe avec ddos par defaut ; si la
                             # separation s'avere utile a l'usage, en faire une
                             # famille a part ("dos_lent") est une option simple
                             # (une seule ligne a changer ici).
    "brute_force": "brute_force",
}

# Colonnes par flux necessaires pour calculer les features fenetre.
REQUIRED = ["SRC_IP", "DST_IP", "PROTOCOL", "DST_PORT", TS, "BIDIRECTIONAL_PACKETS",
            "BIDIRECTIONAL_BYTES", "LABEL"]


def compute_window_features(df: pl.DataFrame, window_ms: int = WINDOW_MS) -> pl.DataFrame:
    """Ajoute les colonnes WIN_* par calcul causal, groupe par SRC_IP.

    Pour chaque flux (trie par horodatage au sein de sa source), on
    maintient une fenetre glissante [t - window_ms, t] grace a deux
    pointeurs (lo/hi) : a chaque flux, on ajoute hi, puis on retire du
    cote lo tout ce qui est sorti de la fenetre. Les compteurs (ports,
    IP destination, protocoles) sont des Counter incrementes/decrementes
    au fil de l'eau, ce qui rend le calcul O(n) par source au lieu de
    recompter toute la fenetre a chaque flux.
    """
    df = df.with_row_index("_row")
    parts: list[pl.DataFrame] = []

    for (_src,), g in df.group_by(["SRC_IP"], maintain_order=False):
        g = g.sort(TS)
        row = g["_row"].to_list()
        ts = g[TS].to_list()
        dport = g["DST_PORT"].to_list()
        dip = g["DST_IP"].to_list()
        proto = g["PROTOCOL"].to_list()
        pkts = g["BIDIRECTIONAL_PACKETS"].to_list()
        byts = g["BIDIRECTIONAL_BYTES"].to_list()
        n = len(ts)

        port_c: Counter = Counter()
        ip_c: Counter = Counter()
        proto_c: Counter = Counter()
        small_n = 0          # flux "petits" (<=2 paquets) dans la fenetre : signature scan
        pkt_sum = 0
        byte_sum = 0
        lo = 0

        flow_count = [0] * n
        dports_d = [0] * n
        dips_d = [0] * n
        small_frac = [0.0] * n
        tcp_frac = [0.0] * n
        udp_frac = [0.0] * n
        icmp_frac = [0.0] * n
        flows_per_s = [0.0] * n
        pkt_sum_col = [0] * n
        byte_sum_col = [0] * n

        for hi in range(n):
            port_c[dport[hi]] += 1
            ip_c[dip[hi]] += 1
            proto_c[proto[hi]] += 1
            if pkts[hi] <= 2:
                small_n += 1
            pkt_sum += pkts[hi]
            byte_sum += byts[hi]

            while ts[hi] - ts[lo] > window_ms:
                port_c[dport[lo]] -= 1
                if port_c[dport[lo]] == 0:
                    del port_c[dport[lo]]
                ip_c[dip[lo]] -= 1
                if ip_c[dip[lo]] == 0:
                    del ip_c[dip[lo]]
                proto_c[proto[lo]] -= 1
                if proto_c[proto[lo]] == 0:
                    del proto_c[proto[lo]]
                if pkts[lo] <= 2:
                    small_n -= 1
                pkt_sum -= pkts[lo]
                byte_sum -= byts[lo]
                lo += 1

            wsize = hi - lo + 1
            span_s = max((ts[hi] - ts[lo]) / 1000, 0.001)  # evite /0 sur le 1er flux

            flow_count[hi] = wsize
            dports_d[hi] = len(port_c)
            dips_d[hi] = len(ip_c)
            small_frac[hi] = small_n / wsize
            tcp_frac[hi] = proto_c.get(6, 0) / wsize
            udp_frac[hi] = proto_c.get(17, 0) / wsize
            icmp_frac[hi] = proto_c.get(1, 0) / wsize
            flows_per_s[hi] = wsize / span_s
            pkt_sum_col[hi] = pkt_sum
            byte_sum_col[hi] = byte_sum

        parts.append(pl.DataFrame({
            "_row": row,
            "WIN_FLOW_COUNT": flow_count,
            "WIN_DISTINCT_DST_PORTS": dports_d,
            "WIN_DISTINCT_DST_IPS": dips_d,
            "WIN_SMALL_FLOW_FRACTION": small_frac,
            "WIN_TCP_FRACTION": tcp_frac,
            "WIN_UDP_FRACTION": udp_frac,
            "WIN_ICMP_FRACTION": icmp_frac,
            "WIN_FLOWS_PER_SEC": flows_per_s,
            "WIN_PACKETS_SUM": pkt_sum_col,
            "WIN_BYTES_SUM": byte_sum_col,
        }))

    win = pl.concat(parts)
    return df.join(win, on="_row").drop("_row").sort(TS)


def main() -> int:
    ap = argparse.ArgumentParser(description="Calcule les features finales du dataset NIDS")
    ap.add_argument("--input", default="clean/dataset_clean.parquet")
    ap.add_argument("--output", default="features/dataset_features.parquet")
    ap.add_argument("--window-ms", type=int, default=WINDOW_MS)
    args = ap.parse_args()

    df = pl.read_parquet(args.input)
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        print(f"[ERREUR] colonnes manquantes dans {args.input} : {missing}")
        return 1

    print(f"[1/3] {df.height:,} flux charges depuis {args.input}")

    df = compute_window_features(df, args.window_ms)
    print(f"[2/3] features de fenetre calculees (fenetre = {args.window_ms/1000:.0f}s, "
          f"groupe par SRC_IP, {df['SRC_IP'].n_unique()} sources distinctes)")

    df = df.with_columns(
        pl.col("LABEL").replace_strict(FAMILY, default="inconnu").alias("LABEL_FAMILY")
    )
    unknown = df.filter(pl.col("LABEL_FAMILY") == "inconnu")
    if unknown.height:
        print(f"[ATTENTION] {unknown.height} flux ont un LABEL sans famille connue : "
              f"{unknown['LABEL'].unique().to_list()} -- ajoute-les dans FAMILY.")

    import os
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    df.write_parquet(args.output)
    print(f"[3/3] [OK] {df.height:,} lignes x {len(df.columns)} colonnes ecrites dans {args.output}")

    with pl.Config(tbl_rows=10, tbl_width_chars=120):
        print("\nRepartition par LABEL :")
        print(df.group_by("LABEL").len().sort("len", descending=True))
        print("\nRepartition par LABEL_FAMILY :")
        print(df.group_by("LABEL_FAMILY").len().sort("len", descending=True))
        print("\nApercu des features de fenetre (mediane par famille) :")
        print(df.group_by("LABEL_FAMILY").agg(
            pl.col("WIN_FLOW_COUNT").median().alias("flow_count_med"),
            pl.col("WIN_DISTINCT_DST_PORTS").median().alias("dports_med"),
            pl.col("WIN_FLOWS_PER_SEC").median().alias("flows_per_s_med"),
            pl.col("WIN_SMALL_FLOW_FRACTION").median().alias("small_frac_med"),
        ).sort("LABEL_FAMILY"))

    return 0


if __name__ == "__main__":
    sys.exit(main())