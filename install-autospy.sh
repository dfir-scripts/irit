#! /bin/bash
mkdir -p /usr/local/src/autopsy
cd /usr/local/src/autopsy
wget -P /usr/local/src/autopsy https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.17.0/autopsy-4.17.0.zip                              
wget -P /usr/local/src/autopsy https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.10.1/sleuthkit-java_4.10.1-1_amd64.deb
unzip /usr/local/src/autopsy/autopsy-4.17.0.zip

apt-get install testdisk -y
wget -q -O - https://download.bell-sw.com/pki/GPG-KEY-bellsoft | sudo apt-key add -
echo "deb [arch=amd64] https://apt.bell-sw.com/ stable main" | sudo tee /etc/apt/sources.list.d/bellsoft.list
apt-get update
apt-get install bellsoft-java8-full
echo "JAVA_HOME=/usr/lib/jvm/bellsoft-java8-full-amd64" >> /etc/environment
apt install ./sleuthkit-java_4.10.1-1_amd64.deb -y

cd /usr/local/src/autopsy/autopsy-4.17.0
sh /usr/local/src/autopsy/autopsy-4.17.0/unix_setup.sh || \
echo "

Autopsy on Linux or OS X Readme says:
NOTE: You may need to log out and back in again after setting JAVA_HOME before the Autopsy unix_setup.sh script can see the value.

To work around, logout and login back in and run the following commands to complete the installation:


cd /usr/local/src/autopsy/autopsy-4.17.0
sudo sh /usr/local/src/autopsy/autopsy-4.17.0/unix_setup.sh
sudo chmod 755 /usr/local/src/autopsy/autopsy-4.17.0/bin/autopsy
sudo cp /usr/local/src/autopsy/bin/autopsy /usr/local/bin/

"
chmod 755 /usr/local/src/autopsy/autopsy-4.17.0/bin/autopsy
cp /usr/local/src/autopsy/autopsy-4.17.0/bin/autopsy /usr/local/bin/
