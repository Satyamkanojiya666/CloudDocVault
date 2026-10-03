#!/usr/bin/env bash
# Run CloudDocVault on your own machine (no AWS needed):  bash run_local.sh
cd "$(dirname "$0")"
[ -d venv ] || python3 -m venv venv
source venv/bin/activate
pip install -q -r requirements-local.txt
if [ ! -f docvault.db ]; then
  read -p "Create demo account with sample files? [y/n]: " d
  [ "$d" = "y" ] && python seed_demo.py
fi
echo "Open http://localhost:5000 in your browser (Ctrl+C to stop)"
python app.py
