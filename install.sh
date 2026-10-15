#!/data/data/com.termux/files/usr/bin/bash

clear

Y='\033[1;33m'
G='\033[1;32m'
R='\033[1;31m'
C='\033[1;36m'
N='\033[0m'

APP="Security 100.py"

echo -e "${Y}"
echo "======================================"
echo "       100X ETHICAL SECURITY"
echo "======================================"
echo -e "${N}"

if [ ! -f "$APP" ]; then
    echo -e "${R}ERROR: $APP not found!${N}"
    echo "Run this installer from the project directory."
    exit 1
fi

echo -e "${C}[1/4] Updating Termux...${N}"
pkg update -y || exit 1

echo -e "${C}[2/4] Installing system packages...${N}"
pkg install -y python git bash nodejs || exit 1

echo -e "${C}[3/4] Installing pip libraries...${N}"
python -m pip install requests colorama colorful || exit 1

echo -e "${C}[4/4] Checking Python syntax...${N}"
python - "$APP" <<'PY'
import ast
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        ast.parse(f.read(), filename=sys.argv[1])
    print("Syntax check: OK")
except (SyntaxError, OSError) as e:
    print(f"Error: {e}")
    sys.exit(1)
PY

if [ "$?" -ne 0 ]; then
    exit 1
fi

echo
echo -e "${G}Installation completed successfully!${N}"
echo -e "${Y}Launch command:${N}"
echo "python 'Security 100.py'"
``` id="dksqpe"