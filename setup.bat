@echo off
echo "Please make sure you have Python 3.x and pip installed and added to your path environment"
echo "Also pls consider switching to Linux :)"
pause

echo "[+] Creating virtual environment"
python -m venv venv

echo "[+] Installing requirements"
venv\Scripts\pip.exe install --upgrade -r requirements.txt

echo "[-] Please manually install Kafka or use the docker-compose file in the collector directory."
echo "For more information please view: https://docs.docker.com/compose/install/"
echo "Afterwards set the use_kafka variable in the config file to 'True'"
echo "Find out how to start the application by visiting your local Windows genie"