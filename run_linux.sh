set -e

cd "$(dirname "$0")"

if ! command -v python3 &> /dev/null; then
    echo "python3 not found. Install it first: sudo apt install python3 python3-venv python3-pip"
    exit 1
fi

if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate
echo "[*] Installing dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r backend/requirements.txt

echo "[*] Checking libpcap (needed by Scapy for live capture)..."
if ! ldconfig -p | grep -q libpcap; then
    echo "    libpcap not detected. You may need: sudo apt install libpcap-dev"
fi

echo "[*] Starting WIRE-CLOUD (root privileges are required for packet capture)..."
sudo "$(pwd)/venv/bin/python" backend/app.py
