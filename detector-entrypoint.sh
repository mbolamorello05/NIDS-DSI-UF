#!/bin/sh
# Superviseur du detecteur (tourne DANS le conteneur, en network_mode: host).
#  1. publie les interfaces reelles de l'hote dans /data/config/interfaces.json
#  2. attend que l'admin ait choisi une interface dans le dashboard
#  3. lance le detecteur ; si le choix change, le relance sur la nouvelle interface
CFG=/data/config/detector_config.json
IFACES=/data/config/interfaces.json
PID=""
trap '[ -n "$PID" ] && kill "$PID" 2>/dev/null; exit 0' TERM INT
mkdir -p /data/config

while true; do
  # 1. (re)publier la liste des interfaces de l'hote
  python /app/realtime_detector_v6.py --list-interfaces --interfaces-out "$IFACES" >/dev/null 2>&1

  # 2. attendre un choix de l'admin
  if ! { [ -s "$CFG" ] && grep -q '"interface"' "$CFG"; }; then
    echo "[superviseur] en attente du choix d'interface (dashboard > Parametres)..."
    while ! { [ -s "$CFG" ] && grep -q '"interface"' "$CFG"; }; do sleep 2; done
  fi

  # 3. lancer le detecteur et surveiller le fichier de config
  HASH=$(md5sum "$CFG" | cut -d' ' -f1)
  echo "[superviseur] demarrage du detecteur : $(tr -d '\n ' < "$CFG")"
  python -u /app/realtime_detector_v6.py --models-dir /app/models \
         --log /data/detections_v6.jsonl --config "$CFG" &
  PID=$!

  while kill -0 "$PID" 2>/dev/null; do
    if [ "$(md5sum "$CFG" | cut -d' ' -f1)" != "$HASH" ]; then
      echo "[superviseur] nouvelle interface choisie -> redemarrage"
      kill "$PID" 2>/dev/null
      break
    fi
    sleep 2
  done
  wait "$PID" 2>/dev/null
  PID=""
  sleep 2   # evite une boucle serree si l'interface est invalide
done