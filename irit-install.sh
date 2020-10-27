#! /bin/bash
function pause(){
 read -s -n 1 -p "Command failed!!!! Press any key to continue . . ."
 echo ""
}

#Irit Tools auto install
#Directories
mkdir -p /mnt/{raw,image_mount,vss,shadow,bde} 
mkdir -p /cases
mkdir -p /usr/local/src/{autopsy,irit/Install,keydet89/tools,yara/Neo23x0/signature-base,yara/yararules.com,/yara/reversinglabs,densityscout,jobparser,malscan,floss,INDXParse,nirsoft,lf}

#apt update and install core package install toosls git, python2, curl, pip, pip3 
apt-get update || pause
apt-get upgrade -q -y -u  || pause
apt-get install git curl python2 -y || pause
#Install pip and pip3
curl https://bootstrap.pypa.io/get-pip.py --output /tmp/get-pip.py
pip -V 2>/dev/null|| python2 /tmp/get-pip.py
pip3 -V 2>/dev/null || apt-get install python3-pip -y 
pip3 -V || pause

#pip package install
irit_pip_pkgs="usnparser oletools libscca-python liblnk-python python-registry pefile libfwsi-python pycrypto yara-python capstone"
for pip_pkg in $irit_pip_pkgs;
do
  pip3 install $pip_pkg || pause
done
pip install analyzeMFT || pause

#PPA 
add-apt-repository -y ppa:linuxgndu/sqlitebrowser || pause

irit_apt_pkgs="net-tools curl git fdupes xpad wxhexeditor mlocate gparted attr sqlite3 gridsite-clients jq chromium-browser graphviz ewf-tools afflib-tools qemu-utils libbde-utils exfat-utils libvshadow-utils xmount cifs-utils guymager libesedb-utils liblnk-utils sqlitebrowser foremost python-wxtools libevtx-utils pff-tools sleuthkit python-jinja2 clamav clamtk rar unrar p7zip-full p7zip-rar wine"
for apt_pkg in $irit_apt_pkgs;
do
  sudo apt-get install $apt_pkg -y 
  dpkg -S $apt_pkg || pause
done

#Git Installs
git clone https://github.com/keydet89/Tools.git /usr/local/src/keydet89/tools/
git clone https://github.com/simsong/bulk_extractor.git /usr/local/src/bulk_extractor 
git clone https://github.com/davidpany/WMI_Forensics.git /usr/local/src/WMI_Forensics
git clone https://github.com/williballenthin/INDXParse.git /usr/local/src/INDXParse
git clone https://github.com/DidierStevens/DidierStevensSuite.git /usr/local/src/DidierStevensSuite
git clone https://github.com/Invoke-IR/PowerForensicsPortable.git /usr/local/src/PowerForensics
git clone https://github.com/volatilityfoundation/volatility.git /usr/local/src/volatility 
git clone https://github.com/volatilityfoundation/volatility3.git /usr/local/src/volatility3
git clone https://github.com/Neo23x0/signature-base.git /usr/local/src/yara/Neo23x0/signature-base
git clone https://github.com/reversinglabs/reversinglabs-yara-rules.git /usr/local/src/yara/reversinglabs
git clone https://github.com/Yara-Rules/rules.git /usr/local/src/yara/yararules.com
git clone https://github.com/jschicht/LogFileParser.git

#wget
wget -O /usr/local/src/irit/ermount.sh https://raw.githubusercontent.com/siftgrab/EverReady-Disk-Mount/master/ermount.sh || pause 
wget -O /usr/local/src/irit/prefetchruncounts.py https://raw.githubusercontent.com/siftgrab/prefetchruncounts/master/prefetchruncounts.py || pause 
wget -O /usr/local/src/irit/winservices.py https://raw.githubusercontent.com/siftgrab/Python-Registry-Extraction/master/winservices.py || pause 
wget -O /usr/local/src/irit/Install/RegRipper30-apt-git-Install.sh https://raw.githubusercontent.com/siftgrab/siftgrab/master/regripper.conf/RegRipper30-apt-git-Install.sh  || pause
wget -O /usr/local/src/densityscout/densityscout_build_45_linux.zip https://cert.at/media/files/downloads/software/densityscout/files/densityscout_build_45_linux.zip || pause
unzip -o /usr/local/src/densityscout/densityscout_build_45_linux.zip 
wget -O /usr/local/src/floss/floss https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/linux/dist/floss || pause 
wget -O /usr/local/src/jobparser/jobparser.py https://raw.githubusercontent.com/gleeda/misc-scripts/master/misc_python/jobparser.py || pause
wget -O /usr/local/src/malscan/installer https://raw.githubusercontent.com/malscan/malscan/1.x/installer
wget -P /usr/local/src/nirsoft/ https://download.nirsoft.net/nirsoft_package_enc_1.23.33.zip || pause
wget https://github.com/gokcehan/lf/releases/download/r17/lf-linux-amd64.tar.gz -O - | tar -xzvf - -C /usr/local/src/lf/
echo -e "unzip -P nirsoft9876$ /usr/local/src/nirsoft/nirsoft_package_enc_1.23.33.zip \n ## Windows utility running with wine\n ##See nirsoft.net website for more info " >> /usr/local/src/nirsoft/README.txt

#fix Windows Perl scripts in Keydet89/Tools/source
find /usr/local/src/keydet89/tools/source -type f 2>/dev/null|grep pl$ | while read d;
do
  file_name=$( echo "$d"|sed 's/\/$//'|awk -F"/" '{print $(NF)}')
  sed -i '/^#! c:[\]perl[\]bin[\]perl.exe/d' $d
  sed -i "1i #!`which perl`" $d
  ln -s $d /usr/local/bin/$file_name
done


#chmods and copy
chmod -R 755 /usr/local/src/irit/*  || pause  
chmod 755 /usr/local/src/WMI_Forensics/*.py || pause 
chmod 755 /usr/local/src/floss/floss || pause 
chmod 755 /usr/local/src/keydet89/tools/source/* || pause
chmod 755 /usr/local/src/jobparser/jobparser.py || pause
cp /usr/local/src/keydet89/tools/source/*.pm /usr/share/perl5
cp /usr/local/src/jobparser/jobparser.py /usr/local/bin/

#Symbolic links
[ -d "/usr/share/irit" ] || ln -s /usr/local/src/irit /usr/share/irit

echo "export PATH=$PATH:/usr/share/keydet89" >> /etc/profile 
cp /usr/bin/python3 /usr/local/bin/python  
[ -f "/usr/local/bin/ermount" ]  || ln -s /usr/local/src/irit/ermount.sh /usr/local/bin/ermount
[ -f "/usr/local/bin/prefetchruncounts.py" ] || ln -s /usr/local/src/irit/prefetchruncounts.py /usr/local/bin/prefetchruncounts.py
[ -f "/usr/local/bin/winservices.py" ] || ln -s /usr/local/src/irit/winservices.py /usr/local/bin/winservices.py
[ -f "/usr/local/bin/CCM_RUA_Finder.py" ] || ln -s /usr/local/src/WMI_Forensics/CCM_RUA_Finder.py /usr/local/bin/CCM_RUA_Finder.py
[ -f "/usr/local/bin/PyWMIPersistenceFinder.py" ] || ln -s /usr/local/src/WMI_Forensics/PyWMIPersistenceFinder.py /usr/local/bin/PyWMIPersistenceFinder.py

#install scripts
/usr/local/src/irit/Install/RegRipper30-apt-git-Install.sh

history -c
