"""
Decoupe le dataset de features en train/test PAR FICHIER DE CAPTURE, puis
entraine les modeles de l'architecture temps reel :
    - modele 1 (binaire)      : benign vs anormal
    - modele(s) 2 (multiclasse): type d'attaque, entraine(s) UNIQUEMENT sur
                                  les flux anormaux (comme realtime_detector_v5.py)

POURQUOI DECOUPER PAR FICHIER
    Dans un flood, les flux se ressemblent presque tous. Un decoupage
    aleatoire flux par flux placerait des flux quasi identiques des deux
    cotes train/test : le score de test serait artificiellement parfait
    et ne dirait rien de la capacite du modele a generaliser. On decoupe
    donc des FICHIERS ENTIERS, jamais vus en entrainement, vers le test.

POURQUOI PAS SRC_IP / DST_IP DANS LES FEATURES
    Si le modele apprend "192.168.148.139 = attaque", il devient inutile
    hors de ce lab. Les features WIN_* (comportement : ports touches,
    flux par seconde...) portent deja le signal utile sans memoriser une
    adresse precise.

GRANULARITE DU MODELE 2 : fine / family / both
    - fine   : un type par attaque (port_scan, icmp_flood, ...). Precis,
               mais icmp_flood/udp_scan ont trop peu de donnees pour une
               evaluation fiable.
    - family : categories larges (scan, ddos, brute_force). Moins precis,
               mais fiable sur toutes les classes.
    - both   : entraine LES DEUX modeles 2 (fichiers *_fine.json et
               *_family.json). Permet d'afficher en temps reel la famille
               (fiable) ET le type detaille (plus precis mais incertain sur
               les classes rares) -- chacun avec sa propre confiance.

UTILISATION
    python train_models.py --input features/dataset_features.parquet --output-dir models --granularity both
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from datetime import datetime, timezone

import numpy as np
import polars as pl
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix

# ============================================================
FEATURE_COLUMNS = [
    # par flux
    "SRC_PORT", "DST_PORT", "PROTOCOL",
    "BIDIRECTIONAL_PACKETS", "BIDIRECTIONAL_BYTES", "BIDIRECTIONAL_DURATION_MS",
    "SRC2DST_PACKETS", "SRC2DST_BYTES", "DST2SRC_PACKETS", "DST2SRC_BYTES",
    # par source / fenetre glissante (voir build_features.py)
    "WIN_FLOW_COUNT", "WIN_DISTINCT_DST_PORTS", "WIN_DISTINCT_DST_IPS",
    "WIN_SMALL_FLOW_FRACTION", "WIN_TCP_FRACTION", "WIN_UDP_FRACTION",
    "WIN_ICMP_FRACTION", "WIN_FLOWS_PER_SEC", "WIN_PACKETS_SUM", "WIN_BYTES_SUM",
]

TEST_FRACTION = 0.25
SEED = 42


def split_by_file(df: pl.DataFrame) -> pl.DataFrame:
    """Assigne chaque flux a 'train' ou 'test' selon le FICHIER qui l'a
    produit, pas au hasard flux par flux. Pour chaque label FIN, on
    repartit les fichiers (jamais les flux) entre train et test ; au moins
    un fichier va dans chaque cote quand c'est possible (impossible si un
    label n'a qu'un seul fichier source -> averti dans le resume). On
    stratifie toujours sur le label FIN (pas la famille), meme en mode
    family/both, pour que chaque type d'attaque soit represente des deux
    cotes independamment de la granularite choisie pour le modele 2."""
    rng = random.Random(SEED)
    assignment: dict[str, str] = {}

    for label in df["LABEL"].unique().sort().to_list():
        files = sorted(df.filter(pl.col("LABEL") == label)["SOURCE_FILE"].unique().to_list())
        rng.shuffle(files)
        if len(files) == 1:
            assignment[files[0]] = "train"
            print(f"  [ATTENTION] '{label}' n'a qu'un seul fichier source "
                  f"({files[0]}) -> tout en train, pas de test pour ce label.")
            continue
        n_test = max(1, round(len(files) * TEST_FRACTION))
        n_test = min(n_test, len(files) - 1)  # garde au moins 1 fichier en train
        for f in files[:n_test]:
            assignment[f] = "test"
        for f in files[n_test:]:
            assignment[f] = "train"

    split_col = df["SOURCE_FILE"].map_elements(lambda f: assignment.get(f, "train"), return_dtype=pl.String)
    return df.with_columns(split_col.alias("SPLIT"))


def balanced_weights(labels: np.ndarray) -> np.ndarray:
    """Poids par echantillon inversement proportionnels a la frequence de
    leur classe, pour que udp_flood (tres frequent) ne noie pas
    icmp_flood/udp_scan (rares) dans la fonction de perte."""
    classes, counts = np.unique(labels, return_counts=True)
    freq = dict(zip(classes, counts))
    total, n_classes = len(labels), len(classes)
    return np.array([total / (n_classes * freq[c]) for c in labels])


def train_model2(train: pl.DataFrame, test: pl.DataFrame, target_col: str,
                  granularity: str, output_dir: str):
    """Entraine un modele 2 (multiclasse) sur la colonne target_col
    (LABEL ou LABEL_FAMILY), l'evalue sur les flux anormaux du test, et
    l'ecrit sous un nom de fichier suffixe par la granularite (fine/family)
    pour pouvoir garder les deux resultats quand --granularity both.
    Retourne le modele et le mapping classe->id (pour la chaine complete)."""
    print("=" * 70)
    print(f"[MODELE 2 - {granularity}] cible = '{target_col}'")
    print("=" * 70)
    train_atk = train.filter(pl.col(target_col) != "benign")
    test_atk = test.filter(pl.col(target_col) != "benign")
    classes = sorted(train_atk[target_col].unique().to_list())
    label_to_id = {c: i for i, c in enumerate(classes)}

    X_train_atk = train_atk.select(FEATURE_COLUMNS).to_numpy()
    y_train_atk = train_atk[target_col].replace_strict(label_to_id).to_numpy()
    missing_test = set(test_atk[target_col].unique().to_list()) - set(classes)
    if missing_test:
        print(f"  [ATTENTION] classes au test absentes du train, ignorees : {missing_test}")
    test_atk = test_atk.filter(pl.col(target_col).is_in(classes))
    X_test_atk = test_atk.select(FEATURE_COLUMNS).to_numpy()
    y_test_atk = test_atk[target_col].replace_strict(label_to_id).to_numpy()

    sw = balanced_weights(y_train_atk)
    print(f"  train: {len(y_train_atk):,} flux anormaux, {len(classes)} classes : {classes}")

    model2 = xgb.XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.1,
        objective="multi:softprob", num_class=len(classes),
        eval_metric="mlogloss", n_jobs=-1, random_state=SEED,
    )
    model2.fit(X_train_atk, y_train_atk, sample_weight=sw)
    pred2 = model2.predict(X_test_atk)
    print("\nRapport (test, fichiers jamais vus) :")
    print(classification_report(y_test_atk, pred2, target_names=classes, digits=3))
    print("Matrice de confusion (lignes=vrai, colonnes=predit) :")
    print(classes)
    print(confusion_matrix(y_test_atk, pred2))

    model2.save_model(os.path.join(output_dir, f"xgb_multiclass_{granularity}.json"))
    with open(os.path.join(output_dir, f"label_encoder_{granularity}.json"), "w") as f:
        json.dump({"granularity": granularity, "target_column": target_col,
                    "classes": label_to_id}, f, indent=2, ensure_ascii=False)

    report_dict = classification_report(y_test_atk, pred2, target_names=classes,
                                         output_dict=True, zero_division=0)
    metrics = {
        "classes": classes,
        "report": report_dict,
        "confusion_matrix": confusion_matrix(y_test_atk, pred2).tolist(),
    }
    return model2, label_to_id, metrics


def main() -> int:
    ap = argparse.ArgumentParser(description="Entraine les modeles NIDS (binaire + multiclasse)")
    ap.add_argument("--input", default="features/dataset_features.parquet")
    ap.add_argument("--output-dir", default="models")
    ap.add_argument("--granularity", choices=["fine", "family", "both"], default="both",
                     help="fine = un type par attaque ; family = categories larges "
                          "(fiable sur les classes rares) ; both = entraine les deux "
                          "(recommande, permet d'afficher famille + type en temps reel).")
    args = ap.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    df = pl.read_parquet(args.input)
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        print(f"[ERREUR] colonnes manquantes : {missing}")
        return 1

    granularities = ["fine", "family"] if args.granularity == "both" else [args.granularity]
    print(f"[granularite(s) du modele 2 : {granularities}]")

    print("=" * 70)
    print("[1/3] DECOUPAGE TRAIN / TEST PAR FICHIER (stratifie sur le label fin)")
    print("=" * 70)
    df = split_by_file(df)
    rep = (df.group_by(["LABEL", "SPLIT"]).len()
           .pivot(index="LABEL", on="SPLIT", values="len").fill_null(0))
    with pl.Config(tbl_rows=10):
        print(rep.sort("LABEL"))

    train = df.filter(pl.col("SPLIT") == "train")
    test = df.filter(pl.col("SPLIT") == "test")
    X_train = train.select(FEATURE_COLUMNS).to_numpy()
    X_test = test.select(FEATURE_COLUMNS).to_numpy()

    # ------------------------------------------------------------
    print("\n" + "=" * 70)
    print("[2/3] MODELE 1 : BINAIRE (benign vs anormal)")
    print("=" * 70)
    y_train_bin = (train["LABEL"] != "benign").to_numpy().astype(int)
    y_test_bin = (test["LABEL"] != "benign").to_numpy().astype(int)

    n_pos, n_neg = y_train_bin.sum(), len(y_train_bin) - y_train_bin.sum()
    scale_pos_weight = n_neg / max(n_pos, 1)
    print(f"  train: {len(y_train_bin):,} flux ({n_pos:,} anormal / {n_neg:,} benign) "
          f"scale_pos_weight={scale_pos_weight:.3f}")

    model1 = xgb.XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.1,
        scale_pos_weight=scale_pos_weight, eval_metric="logloss",
        n_jobs=-1, random_state=SEED,
    )
    model1.fit(X_train, y_train_bin)
    pred1 = model1.predict(X_test)
    print("\nRapport (test, fichiers jamais vus) :")
    print(classification_report(y_test_bin, pred1, target_names=["benign", "anormal"], digits=3))
    model1.save_model(os.path.join(args.output_dir, "xgb_binary.json"))
    model1_report = classification_report(y_test_bin, pred1, target_names=["benign", "anormal"],
                                           output_dict=True, zero_division=0)

    # ------------------------------------------------------------
    print("\n" + "=" * 70)
    print("[3/3] MODELE(S) 2 + CHAINE COMPLETE")
    print("=" * 70)
    sub = test.filter(pl.Series(pred1 == 1))
    X_sub = sub.select(FEATURE_COLUMNS).to_numpy() if sub.height else None

    model2_metrics = {}
    full_chain_metrics = {}
    for granularity in granularities:
        target_col = "LABEL" if granularity == "fine" else "LABEL_FAMILY"
        model2, label_to_id, m2_metrics = train_model2(train, test, target_col, granularity, args.output_dir)
        model2_metrics[granularity] = m2_metrics
        id_to_label = {v: k for k, v in label_to_id.items()}

        print(f"\n--- Chaine complete (modele 1 -> modele 2 [{granularity}]) ---")
        full_pred = np.array(["benign"] * len(test), dtype=object)
        if X_sub is not None:
            pred_sub = model2.predict(X_sub)
            full_pred[pred1 == 1] = [id_to_label[p] for p in pred_sub]
        y_true_full = test[target_col].to_numpy()
        print(classification_report(y_true_full, full_pred, digits=3, zero_division=0))
        full_chain_metrics[granularity] = classification_report(
            y_true_full, full_pred, output_dict=True, zero_division=0)

    with open(os.path.join(args.output_dir, "feature_columns.json"), "w") as f:
        json.dump(FEATURE_COLUMNS, f, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------
    # Metriques sauvegardees pour la section "Performance du modele" du
    # dashboard : pas de chiffres recalcules ou inventes cote frontend,
    # juste ce qui vient reellement de cet entrainement.
    dataset_summary = {
        "total_flows": df.height,
        "by_label": {k: v for k, v in df.group_by("LABEL").len().iter_rows()},
        "by_family": {k: v for k, v in df.group_by("LABEL_FAMILY").len().iter_rows()},
    }
    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset": dataset_summary,
        "model1_binary": {"report": model1_report},
        "model2": model2_metrics,          # cle = granularite ("fine"/"family")
        "full_chain": full_chain_metrics,  # cle = granularite
    }
    with open(os.path.join(args.output_dir, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)

    print(f"\n[OK] Modeles et metadonnees ecrits dans {args.output_dir}/")
    print(f"     -> metrics.json : donnees pour la section Performance du dashboard")
    if args.granularity == "both":
        print("     -> xgb_multiclass_fine.json + xgb_multiclass_family.json : "
              "le detecteur temps reel peut interroger les deux et afficher "
              "famille + type detaille, chacun avec sa propre confiance.")
    return 0


if __name__ == "__main__":
    sys.exit(main())