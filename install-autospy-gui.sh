#! /bin/bash
# This downloads and installs the latest version of Autopsy 
get_install_state(){
which autopsy && echo "A version of autopsy is already installed!!!" read -s -n 1 -p " Press any key to continue or ctrl-c to exit"
}

download_autopsy(){
mkdir -p /usr/local/src/autopsy
cd /usr/local/src/autopsy 
[ "$(ls /usr/local/src/autopsy/$autopsy_release.zip 2>/dev/null )" ] || \
wget -P /usr/local/src/autopsy https://github.com/$autopsy_download
[ "$(ls -A /usr/local/src/autopsy/$autopsy_release )" ] && \
echo "Autopsy files exist" || \
unzip /usr/local/src/autopsy/$autopsy_release.zip                            

[ "$(ls /usr/local/src/autopsy/$sleuthkit_release 2>/dev/null )" ] && \
echo "Sleuthkit install file exists" ||
wget -P /usr/local/src/autopsy https://github.com/$sleuthkit_download
}

run_install(){
apt-get install testdisk -y
wget -q -O - https://download.bell-sw.com/pki/GPG-KEY-bellsoft | sudo apt-key add -
echo "deb [arch=amd64] https://apt.bell-sw.com/ stable main" | sudo tee /etc/apt/sources.list.d/bellsoft.list
apt-get update
apt-get install bellsoft-java8-full
echo "JAVA_HOME=/usr/lib/jvm/bellsoft-java8-full-amd64" >> /etc/environment
apt install ./$sleuthkit_release -y

cd /usr/local/src/autopsy/$autopsy_release
chmod 755 /usr/local/src/autopsy/$autopsy_release/unix_setup.sh
sh /usr/local/src/autopsy/$autopsy_release/unix_setup.sh || \
echo "

The Autopsy help file, \"Running_Linux_OSX.txt\" contains the following statement:

NOTE: You may need to log out and back in again after setting JAVA_HOME before the Autopsy unix_setup.sh script can see the value.

the path to unix_setup.sh is:
/usr/local/src/autopsy/$autopsy_release/unix_setup.sh

Alternatively you can reboot and rerun install-autopsy-gui.sh"
}


#chmod 755 /usr/local/src/autopsy/$$autopsy_latest/bin/autopsy
#cp /usr/local/src/autopsy/$$autopsy_latest/bin/autopsy /usr/local/bin/


[ $(whoami) != "root" ] && echo "Requires Root!" && exit
echo "requires curl"
which curl || exit
clear
autopsy_download=$(curl -s https://github.com/sleuthkit/autopsy/releases | grep -o /sleuthkit/autopsy/releases/download/autopsy.*.zip|head -n 1)
autopsy_release=$(echo $autopsy_download |awk -F'/' '{print $NF}'|awk -F'.zip' '{print$1}') 
echo "Autopsy Latest GUI Version"
echo $autopsy_release

sleuthkit_download=$(curl -s https://github.com/sleuthkit/sleuthkit/releases/ | grep -o /sleuthkit/sleuthkit/releases/download/.*amd64.deb |head -n 1)
sleuthkit_release=$(echo $sleuthkit_download |awk -F'/' '{print $NF}')
echo "Sleuthkit Latest Java Version"
echo $sleuthkit_release


get_install_state
download_autopsy
run_install
