#! /bin/bash
function pause(){
 read -s -n 1 -p "Command failed!!!! Press any key to continue . . ."
 echo ""
}

############### Irit Tools auto install ##########################
#Make Directories
mkdir -p /mnt/{raw,image_mount,vss,shadow,bde} 
mkdir -p /cases
mkdir -p /usr/local/src/{autopsy,LogFileParser,irit/Install,keydet89/tools,yara/Neo23x0/signature-base,yara/yararules.com,/yara/reversinglabs,densityscout,jobparser,malscan,floss,INDXParse,nirsoft,lf,cyberchef}


#apt update and install core package install toosls git, python2, curl, pip, pip3 
apt-get update || pause
apt-get upgrade -q -y -u  || pause
apt-get install git curl python2 -y || pause

#Set python3 as python and Install pip and pip3
cp /usr/bin/python3 /usr/local/bin/python 
curl https://bootstrap.pypa.io/get-pip.py --output /tmp/get-pip.py
pip -V 2>/dev/null|| python2 /tmp/get-pip.py
pip3 -V 2>/dev/null || apt-get install python3-pip -y 
pip3 -V || pause

#pip package install and update
# PIP version 3 = pip3
irit_pip_pkgs="usnparser oletools libscca-python liblnk-python python-registry pefile libfwsi-python pycrypto yara-python capstone"
for pip_pkg in $irit_pip_pkgs;
do
  pip3 install $pip_pkg || pause
done
# PIP version 2 = pip
pip install analyzeMFT || pause

#Apt Package Installations
#PPA 
add-apt-repository -y ppa:linuxgndu/sqlitebrowser || pause
add-apt-repository -y ppa:papirus/papirus  || pause

irit_apt_pkgs="dconf* net-tools curl git vim fdupes xpad gnome-terminal gnome-shell-extensions gnome-tweaks pcmanfm stegosuite yara gddrescue sleuthkit open-vm-tools-desktop gedit wxhexeditor mlocate gparted attr gridsite-clients jq chromium-browser graphviz ewf-tools afflib-tools qemu-utils libbde-utils exfat-utils libvshadow-utils xmount cifs-utils guymager libesedb-utils liblnk-utils sqlitebrowser foremost testdisk ifuse python-wxtools libevtx-utils pff-tools sleuthkit python-jinja2 clamav clamtk rar unrar p7zip-full p7zip-rar papirus-icon-theme wine sqlite3 npm"
for apt_pkg in $irit_apt_pkgs;
do
  sudo apt-get install $apt_pkg -y 
  dpkg -S $apt_pkg || pause
done

# Snap installs
sudo snap install powershell --classic

#Git and configure Package Installations and Updates

#Git and configure Harlan Carvey tools
[ "$(ls -A /usr/local/src/keydet89/tools/)" ] && \
git -C /usr/local/src/keydet89/tools/ pull || \
git clone https://github.com/keydet89/Tools.git /usr/local/src/keydet89/tools/ 
chmod 755 /usr/local/src/keydet89/tools/source/* || pause
#set Windows Perl scripts in Keydet89/Tools/source 
find /usr/local/src/keydet89/tools/source -type f 2>/dev/null|grep pl$ | while read d;
do
  file_name=$( echo "$d"|sed 's/\/$//'|awk -F"/" '{print $(NF)}')
  sed -i '/^#! c:[\]perl[\]bin[\]perl.exe/d' $d && sed -i "1i #!`which perl`" $d
  cp $d /usr/local/bin/$file_name
done
cp /usr/local/src/keydet89/tools/source/*.pm /usr/share/perl/5.30/

# git bulk extractor
[ "$(ls -A /usr/local/src/bulk_extractor/)" ] && \
git -C /usr/local/src/bulk_extractor pull || \ 
git clone https://github.com/simsong/bulk_extractor.git /usr/local/src/bulk_extractor 
# Requires a manual install bulk extractor

#Git and configure WMI Forensics
[ "$(ls -A /usr/local/src/WMI_Forensics/)" ] && \
git -C /usr/local/src/WMI_Forensics pull || \
git clone https://github.com/davidpany/WMI_Forensics.git /usr/local/src/WMI_Forensics
chmod 755 /usr/local/src/WMI_Forensics/*.py
[ -f "/usr/local/bin/CCM_RUA_Finder.py" ] || cp /usr/local/src/WMI_Forensics/CCM_RUA_Finder.py /usr/local/bin/CCM_RUA_Finder.py
[ -f "/usr/local/bin/PyWMIPersistenceFinder.py" ] || cp /usr/local/src/WMI_Forensics/PyWMIPersistenceFinder.py /usr/local/bin/PyWMIPersistenceFinder.py

#Git and configure INDXParse
[ "$(ls -A /usr/local/src/INDXParse/)" ] && \
git -C /usr/local/src/INDXParse pull ||\
git clone https://github.com/williballenthin/INDXParse.git /usr/local/src/INDXParse

#Git and configure Didier Stevens Tools
[ "$(ls -A /usr/local/src/DidierStevensSuite/)" ] && \
git -C /usr/local/src/DidierStevensSuite pull || \
git clone https://github.com/DidierStevens/DidierStevensSuite.git /usr/local/src/DidierStevensSuite

#Git CyLR
[ "$(ls -A /usr/local/src/CyLR/)" ] && \
git -C https://github.com/orlikoski/CyLR.git pull || \
git clone https://github.com/orlikoski/CyLR.git  /usr/local/src/CyLR

#Git Volatility 2 and 3
[ "$(ls -A /usr/local/src/volatility/)" ] && \
git -C /usr/local/src/volatility pull || \
git clone https://github.com/volatilityfoundation/volatility.git /usr/local/src/volatility 
chmod 755  /usr/local/src/volatility/*.py 
[ "$(ls -A /usr/local/src/volatility3/)" ] && \
git -C /usr/local/src/volatility3 pull || \
git clone https://github.com/volatilityfoundation/volatility3.git /usr/local/src/volatility3
chmod 755  /usr/local/src/volatility/*.py

#Git Yara Rules
[ "$(ls -A /usr/local/src/yara/Neo23x0/signature-base/)" ] && \
git -C /usr/local/src/yara/Neo23x0/signature-base pull|| \
git clone https://github.com/Neo23x0/signature-base.git /usr/local/src/yara/Neo23x0/signature-base
[ "$(ls -A /usr/local/src/yara/reversinglabs/)" ] && \
git -C /usr/local/src/yara/reversinglabs pull || \
git clone https://github.com/reversinglabs/reversinglabs-yara-rules.git /usr/local/src/yara/reversinglabs
[ "$(ls -A /usr/local/src/yara/yararules.com/)" ] && \
git -C /usr/local/src/yara/yararules.com pull || \
git clone https://github.com/Yara-Rules/rules.git /usr/local/src/yara/yararules.com

#Git LogFileParser
[ "$(ls -A /usr/local/src/LogFileParser/)" ] && \
git -C /usr/local/src/LogFileParser pull|| \
git clone https://github.com/jschicht/LogFileParser.git /usr/local/src/LogFileParser

#Git kacos200 Scripts
[ "$(ls -A /usr/local/src/kacos2000/Queries)" ] && \
git -C /usr/local/src/kacos2000/Queries pull|| \
git clone https://github.com/kacos2000/Queries.git /usr/local/src/kacos2000/Queries

[ "$(ls -A /usr/local/src/kacos2000/WindowsTimeline)" ] && \
git -C /usr/local/src/kacos2000/WindowsTimeline pull|| \
git clone https://github.com/kacos2000/WindowsTimeline.git /usr/local/src/kacos2000/WindowsTimeline

[ "$(ls -A /usr/local/src/cugu/afro )" ] && \
git -C /usr/local/src/cugu/afro || \
git clone https://github.com/cugu/afro.git /usr/local/src/cugu/afro

#wget
# Get IRIT Tools
wget -O /tmp/PowerForensics.zip https://github.com/Invoke-IR/PowerForensics/releases/download/1.1.1/PowerForensics.zip
unzip -o /tmp/PowerForensics.zip -d /root/.local/share/powershell/Modules/ && rm /tmp/PowerForensics.zip
wget -O /usr/local/src/irit/siftgrab.sh https://raw.githubusercontent.com/siftgrab/irit/main/siftgrab.sh || pause 
wget -O /usr/local/src/irit/ermount.sh https://raw.githubusercontent.com/siftgrab/EverReady-Disk-Mount/master/ermount.sh || pause 
wget -O /usr/local/src/irit/prefetchruncounts.py https://raw.githubusercontent.com/siftgrab/prefetchruncounts/master/prefetchruncounts.py || pause 
wget -O /usr/local/src/irit/winservices.py https://raw.githubusercontent.com/siftgrab/Python-Registry-Extraction/master/winservices.py || pause 
wget -O /usr/local/src/irit/Install/RegRipper30-apt-git-Install.sh https://raw.githubusercontent.com/siftgrab/siftgrab/master/regripper.conf/RegRipper30-apt-git-Install.sh  || pause
wget -O /usr/local/src/irit/Install/install-autospy.sh  https://raw.githubusercontent.com/siftgrab/irit/main/install-autospy.sh  || pause
chmod -R 755 /usr/local/src/irit/*  || pause 
[ -f "/usr/local/bin/siftgrab.sh" ]  ||cp /usr/local/src/irit/siftgrab.sh /usr/local/bin/siftgrab
[ -f "/usr/local/bin/ermount" ]  ||cp /usr/local/src/irit/ermount.sh /usr/local/bin/ermount
[ -f "/usr/local/bin/prefetchruncounts.py" ] || cp /usr/local/src/irit/prefetchruncounts.py /usr/local/bin/prefetchruncounts.py
[ -f "/usr/local/bin/winservices.py" ] || cp /usr/local/src/irit/winservices.py /usr/local/bin/winservices.py
#install RegRipper.git and configure RegRipper
/usr/local/src/irit/Install/RegRipper30-apt-git-Install.sh
 
# Get Density Scout
wget -O /usr/local/src/densityscout/densityscout_build_45_linux.zip https://cert.at/media/files/downloads/software/densityscout/files/densityscout_build_45_linux.zip || pause
unzip -o /usr/local/src/densityscout/densityscout_build_45_linux.zip -d /usr/local/src/densityscout/ && rm  /usr/local/src/densityscout/densityscout_build_45_linux.zip
# Get Floss
wget -O /usr/local/src/floss/floss https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/linux/dist/floss || pause 
chmod 755 /usr/local/src/floss/floss || pause
cp /usr/local/src/floss/floss /usr/local/bin/ || pause
# Get Job Parser
wget -O /usr/local/src/jobparser/jobparser.py https://raw.githubusercontent.com/gleeda/misc-scripts/master/misc_python/jobparser.py || pause
#chmod 755 /usr/local/src/jobparser/jobparser.py || pause
cp /usr/local/src/jobparser/jobparser.py /usr/local/bin/
# Get Malscan
wget -O /usr/local/src/malscan/installer https://raw.githubusercontent.com/malscan/malscan/1.x/installer  || pause
chmod 755 /usr/local/src/malscan/installer
# Get Nirsoft Suite
wget -O /usr/local/src/nirsoft/nirsoft_package_enc_1.23.33.zip https://download.nirsoft.net/nirsoft_package_enc_1.23.33.zip || pause
#echo -e "unzip -P nirsoft9876$ /usr/local/src/nirsoft/nirsoft_package_enc_1.23.33.zip \n ## Windows utility running with wine\n ##See nirsoft.net website for more info " >> /usr/local/src/nirsoft/README.txt
#Require manual install
#Get lf File Browser
wget https://github.com/gokcehan/lf/releases/download/r17/lf-linux-amd64.tar.gz -O - | tar -xzvf - -C /usr/local/src/lf/
sudo cp  /usr/local/src/lf/lf /usr/local/bin/
#Get CyberChef
wget -O /usr/local/src/cyberchef/CyberChef_v9.21.0.zip https://github.com/gchq/CyberChef/releases/download/v9.21.0/CyberChef_v9.21.0.zip || pause
unzip -o /usr/local/src/cyberchef/CyberChef_v9.21.0.zip -d /usr/local/src/cyberchef && rm /usr/local/src/cyberchef/CyberChef_v9.21.0.zip

#Symbolic links
[ -d "/opt/share" ] || ln -s /usr/local/src/ /opt/share

#desktop
#cp wallpaper
#cp shortcutss and settings for desktop
#install themes
history -c
