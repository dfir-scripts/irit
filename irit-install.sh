#! /bin/bash
function pause(){
 read -s -n 1 -p "Command failed!!!! Press any key to continue . . ."
 echo ""
}

#Irit Tools auto install
#Directories
mkdir -p /mnt/{raw,image_mount,vss,shadow,bde} 
mkdir /cases
mkdir -p /usr/local/src/{autopsy,irit/Install,keydet89/tools,yara/Neo23x0/signature-base,yara/yararules.com,densityscout,floss,INDXParse,jobparser}

#apt # apt-get || pause
apt-get update || pause
apt-get upgrade -q -y -u  || pause
#PPA 
add-apt-repository -y ppa:linuxgndu/sqlitebrowser || pause
irit_apt_pkgs="net-tools curl ranger git python3-pip fdupes xpad bless mlocate gparted attr sqlite3 jq chromium-browser graphviz ewf-tools afflib-tools qemu-utils libbde-utils exfat-utils libvshadow-utils xmount cifs-utils guymager libesedb-utils liblnk-utils install ubuntu-restricted-extras sqlitebrowser foremost libevtx-utils pff-tools clamav clamtk rar unrar p7zip-full p7zip-rar wine winetricks"
for apt_pkg in $irit_apt_pkgs;
do
  sudo apt-get install $apt_pkg -y 
  dpkg -S $apt_pkg || pause
done

#Git Installs
git clone https://github.com/keydet89/Tools.git /usr/local/src/
git clone https://github.com/simsong/bulk_extractor.git /usr/local/src/bulk_extractor 
git clone https://github.com/davidpany/WMI_Forensics.git /usr/local/src/WMI_Forensics
git clone https://github.com/williballenthin/INDXParse.git /usr/local/src/INDXParse
git clone https://github.com/DidierStevens/DidierStevensSuite.git /usr/local/src/DidierStevensSuite
git clone https://github.com/Invoke-IR/PowerForensicsPortable.git /usr/local/src/PowerForensics
git clone https://github.com/eddsalkield/analyzeMFT3.git /usr/local/src/analyzeMFT3
git clone https://github.com/volatilityfoundation/volatility.git /usr/local/src/volatility 
git clone https://github.com/volatilityfoundation/volatility3.git /usr/local/src/volatility3
git clone https://github.com/Neo23x0/signature-base.git /usr/local/src/yara/Neo23x0/signature-base
git clone https://github.com/Yara-Rules/rules.git /usr/local/src/yara/yararules.com

#wget
wget -O /usr/local/src/irit/ermount.sh https://raw.githubusercontent.com/siftgrab/EverReady-Disk-Mount/master/ermount.sh || pause 
wget -O /usr/local/src/irit/prefetchruncounts.py https://raw.githubusercontent.com/siftgrab/prefetchruncounts/master/prefetchruncounts.py || pause 
wget -O /usr/local/src/irit/winservices.py https://raw.githubusercontent.com/siftgrab/Python-Registry-Extraction/master/winservices.py || pause 
wget -O /usr/local/src/irit/Install/RegRipper30-apt-git-Install.sh https://raw.githubusercontent.com/siftgrab/siftgrab/master/regripper.conf/RegRipper30-apt-git-Install.sh  || pause
wget -P /usr/local/src/densityscout/ https://cert.at/media/files/downloads/software/densityscout/files/densityscout_build_45_linux.zip || pause
unzip  /usr/local/src/densityscout/densityscout_build_45_linux.zip 
wget -P /usr/local/src/floss/ https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/linux/dist/floss || pause 
wget -P /usr/local/src/jobparser/ https://raw.githubusercontent.com/gleeda/misc-scripts/master/misc_python/jobparser.py || pause
#wget -P /usr/local/src/nirsoft/ https://download.nirsoft.net/nirsoft_package_enc_1.23.33.zip || pause
#unzip -P nirsoft9876$ /usr/local/src/nirsoft/nirsoft_package_enc_1.23.33.zip
chmod -R 755 /usr/local/src/irit/*  || pause  
chmod 755 /usr/local/src/WMI_Forensics/*.py || pause 
chmod 755 /usr/local/src/analyzeMFT3/analyzeMFT.py || pause 
chmod 755 /usr/local/src/floss/floss || pause 

#Symbolic links
[ -d "/usr/share/irit" ] || ln -s /usr/local/src/irit /usr/share/irit
cp /usr/bin/python3 /usr/local/bin/python  
[ -f "/usr/bin/pip" ] || ln -s /usr/bin/pip3 /usr/bin/pip
[ -f "/usr/local/bin/ermount" ]  || ln -s /usr/local/src/irit/ermount.sh /usr/local/bin/ermount
[ -f "/usr/local/bin/prefetchruncounts.py" ] || ln -s /usr/local/src/irit/prefetchruncounts.py /usr/local/bin/prefetchruncounts.py
[ -f "/usr/local/bin/winservices.py" ] || ln -s /usr/local/src/irit/winservices.py /usr/local/bin/winservices.py
[ -f "/usr/local/bin/CCM_RUA_Finder.py" ] || ln -s /usr/local/src/WMI_Forensics/CCM_RUA_Finder.py /usr/local/bin/CCM_RUA_Finder.py
[ -f "/usr/local/bin/PyWMIPersistenceFinder.py" ] || ln -s /usr/local/src/WMI_Forensics/PyWMIPersistenceFinder.py /usr/local/bin/PyWMIPersistenceFinder.py
[ -f "/usr/local/bin/analyzeMFT.py" ] || ln -s  /usr/local/src/analyzeMFT3/analyzeMFT.py /usr/local/bin/analyzeMFT.py 

cp /usr/share/applications/bless.desktop /home/analyst/Desktop/ || pause
cp /usr/share/applications/sqlitebrowser.desktop /home/analyst/Desktop/  || pause
cp /usr/share/applications/ranger.desktop /home/analyst/Desktop/ || pause



#pip package install
irit_pip_pkgs="usnparser oletools libscca-python liblnk-python python-registry pefile libfwsi-python pycrypto yara-python"

for pip_pkg in $irit_pip_pkgs;
do
  pip install $pip_pkg
done


#install scripts
/usr/local/src/irit/Install/RegRipper30-apt-git-Install.sh
history -c
