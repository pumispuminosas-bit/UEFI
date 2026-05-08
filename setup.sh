#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT_DIR"

echo "[+] Setting up Universal UEFI Sanitizer..."

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is not installed. Install Python 3.11+ and rerun this script."
  exit 1
fi

if [ ! -d "venv" ]; then
  echo "[+] Creating Python virtual environment..."
  python3 -m venv venv
fi

source venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt

if [ ! -d "me_cleaner" ]; then
  echo "[+] Downloading me_cleaner..."
  git clone https://github.com/corna/me_cleaner.git me_cleaner
else
  echo "[+] me_cleaner already exists, skipping clone."
fi

if [ -f "me_cleaner/me_cleaner.py" ]; then
  chmod +x me_cleaner/me_cleaner.py
fi

cat <<'EOF'

Setup complete!

Next steps:
  source venv/bin/activate
  ./run.sh --help

Run the universal sanitization workflow like this:
  ./run.sh universal-sanitize firmware.bin --vendor lenovo --output-dir sanitized_output
EOF
