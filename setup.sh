#!/usr/bin/env bash
if [ -n "$1" ]; then
  echo "Using containerised setup";
  pip install --upgrade -r requirements.txt
  exit
else
  echo "Using local setup";
fi

if hash python3 2>/dev/null; then
    echo "[+] Python 3 is installed"
else
    sudo apt-get install python3 python3-pip
fi
sudo python3 -m pip install venv

if [[ -d venv ]]
then
    echo "[*] venv already set-up, upgrading packages"
    source venv/bin/activate
    pip install --upgrade -r requirements.txt
else
    echo "[+] Creating virtual environment"
    python3 -m venv venv
    source venv/bin/activate
    echo "[+] Installing requirements"
    pip install -r requirements.txt
fi

read -p "Would you like to install and start the collector agent using docker-compose? " -n 1 -r
echo    # (optional) move to a new line
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    cd collector || exit
    echo "[+] Installing Kafka"
    sudo docker-compose up -d
else
  echo "If you would like to use the HTTP collector later you can manually install Kafka or use the docker-compose file in the collector directory."
fi

echo "All ready :)"