apt-get update
apt-get install git -y
apt-get install libbluetooth-dev -y
apt-get install python-setuptools -y
apt-get install python-dev -y
apt-get install python-glade2 -y
apt-get install python-rsa -y
cd ~/
git clone https://github.com/karulis/pybluez.git
cd pybluez
python setup.py install
