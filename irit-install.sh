# Siftgrab Install Script
#Verify root
[ `whoami` != 'root' ] && echo "Irit install requires root access!" && exit

#sqlite browser repo
add-apt-repository -y ppa:linuxgndu/sqlitebrowser  

# Add Gift repository
#add-apt-repository ppa:gift/stable -y -u || read -n1 -r -p "Command failed!!!! Press a key to continue..." key
# apt-get install plaso-tools -y || read -n1 -r -p "Command failed!!!! Press a key to continue..." key

apt-get update 
apt-get upgrade -q -y -u 

# Create Target Directories
mkdir -p /mnt/{raw,image_mount,vss,shadow,bde} /cases 
mkdir -p /usr/local/src/irit/Install 
#Make a symbolic link for irit
ln -s /usr/local/src/irit /usr/share/irit 


# Apt repo install
# Install Operatin system and General Purpose Utilities
sudo apt-get install net-tools curl ranger git python3-pip fdupes xpad bless mlocate gparted attr sqlite3 jq chromium-browser graphviz -y 

# Install Disk Mounting 
sudo apt-get install ewf-tools afflib-tools qemu-utils libbde-utils exfat-utils libvshadow-utils xmount cifs-utils guymager -y 

#Install misc forensic tools
sudo apt-get install libesedb-utils liblnk-utils sqlitebrowser foremost libevtx-utils pff-tools autopsy -y 

# Download irit tools to /usr/local/src/irit 
sudo wget -O /usr/local/src/irit/ermount.sh https://raw.githubusercontent.com/siftgrab/EverReady-Disk-Mount/master/ermount.sh   
sudo wget -O /usr/local/src/irit/prefetchruncounts.py https://raw.githubusercontent.com/siftgrab/prefetchruncounts/master/prefetchruncounts.py 
sudo wget -O /usr/local/src/irit/winservices.py https://raw.githubusercontent.com/siftgrab/Python-Registry-Extraction/master/winservices.py 
wget -O /usr/local/src/irit/Install/RegRipper30-apt-git-Install.sh https://raw.githubusercontent.com/siftgrab/siftgrab/master/regripper.conf/RegRipper30-apt-git-Install.sh || read -n1 -r -p "Command failed!!!! Press a key to continue..." key

#make irit tools executable and copy to /usr/local/bin/
chmod -R 755 /usr/local/src/irit/* || read -n1 -r -p "Command failed!!!! Press a key to continue..." key
cp /usr/local/src/irit/ermount.sh /usr/local/bin/ermount 
cp /usr/local/src/irit/prefetchruncounts.py /usr/local/bin/ 
cp /usr/local/src/irit/winservices.py /usr/local/bin/ 

#Install Regripper 3.0 
/usr/local/src/irit/Install/RegRipper30-apt-git-Install.sh 

#Download Keydet89 tools
mkdir -p /usr/local/src/keydet89 
cd /usr/local/src/keydet89 
git clone https://github.com/keydet89/Tools.git 

#Download from github
cd .. 
git clone --recursive https://github.com/simsong/bulk_extractor.git 
cd bulk_extractor
chmod -R 755 *
bash /etc/CONFIGURE_UBUNTU18.bash
bootstrap.sh
./configure
make 
make install

cd ..

git clone https://github.com/davidpany/WMI_Forensics.git 
git clone https://github.com/williballenthin/INDXParse.git 
git clone https://github.com/dkovar/analyzeMFT.git 
git clone https://github.com/DidierStevens/DidierStevensSuite.git
git clone https://github.com/Invoke-IR/PowerForensicsPortable.git
git clone https://github.com/eddsalkield/analyzeMFT3.git  


chmod 755 /usr/local/src/WMI_Forensics/*.py
cp /usr/local/src/WMI_Forensics/*.py /usr/local/bin/
chmod 755 /usr/local/src/analyzeMFT3/analyzeMFT.py
cp /usr/local/src/analyzeMFT3/analyzeMFT.py /usr/local/bin/


#Wget misc files and apps
mkdir densityscout 
cd densityscout 
wget -c https://cert.at/media/files/downloads/software/densityscout/files/densityscout_build_45_linux.zip  \
&& unzip densityscout_build_45_linux.zip
chmod 755 lin64/densityscout
chmod 755 lin32/densityscout
cd .. 
mkdir floss 
cd floss 
wget wget -O /usr/local/src/floss/floss https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/linux/dist/floss 
chmod 755 /usr/local/src/floss/floss

#Set python3 as default and install python packages
cp /usr/bin/python3 /usr/local/bin/python 
pip3 install usnparser 
pip3 install -U oletools 
pip3 install libscca-python 
pip3 install liblnk-python 
pip3 install python-registry 
pip3 install pefile
pip3 install libfwsi-python


# Install ClamAV
apt-get install clamav clamtk -y 

#Install Powershell and Power Forensics
snap install powershell --classic 

updatedb


# Optional File Edits
# Enable File Sharing in VMWare options
# Add line to last line of  etc/fstab
  #echo "vmhgfs-fuse    /mnt/hgfs    fuse    defaults,nonempty,allow_other 0 0” >> etc/fstab
