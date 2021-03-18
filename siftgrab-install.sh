#! /bin/bash

<< ////
Siftgrab and basic IR triage tools download script

Siftgrab Parsers (output TLN)
# $MFT Parsers (AnalyzeMFT,MFT_Dump)
# $USNJRNL (usnparser.py)
# Registry Parsers (Regripper 3.0, built-in)
# Usrclass.dat
# amcache.hve
# Srudb.dat (esedbexport)
# Webcachev.dat (esedbexport)
# Alternate Data Streams 
# Prefetch (prefetchruncounts.py)
# Chrome and Firefox
# lnk files (lnkinfo)
# Index.dat (parseie.pl)
# Windows Event Logs (
# RecycleBin
# OBJECTS.DATA (PyWMIPersistenceFinder.py,CCM_RUA_Finder.py)
# Outlook Mailbox Extraction (pff-tools)
# Scheduled Tasks (jobparser.py)


#directories created
#  /mnt/raw 
#  /mnt/image_mount
#  /mnt/vss
#  /mnt/shadow
#  /mnt/bde
#  /cases


////

function display_usage(){
  clear
  echo "
  Siftgrab-install.sh 
  Running this script will download files 
  needed to install and run siftgrab onto Debian x86_64 based systems
  
  USAGE: Siftgrab-install.sh -h -t

         -t Installs additional forensic tools
         -i Installs additional forensic tools and irit gui (work in pprogress)		 
         -h Displays this help text
		 
		 "
    exit
}	

function pause(){
 read -s -n 1 -p "Command failed!!!! Press any key to continue . . ."
 echo ""
}

function install_powershell(){  
  hostname |grep kali && \
  apt install powershell -y || \
  apt install snapd -y &&\   
  snap install powershell --classic
  pwsh -v || pause
}

function main_install(){
  apt-get update || pause
  apt-get upgrade -q -y -u  || pause
  apt-get install git curl python2 net-tools vim mlocate  -y || pause
  
  #Set python3 as python and Install pip and pip3
  echo "Requires python2 for legacy scripts"
  echo "Assumes python3 is installed"
  which python3 && which python2 || pause
  
  ############### Siftgrab Tools Download, Install and Confiuration ##########################
  #Make Disk Mount and Cases Directories
  mkdir -p /mnt/{raw,image_mount,vss,shadow,bde}
  mkdir -p /cases

  #Install pip and pip3
  pip3 -V 2>/dev/null || apt-get install python3-pip -y 
  pip3 -V || pause
  
  #pip installs
  sift_pip_pkgs="usnparser libscca-python liblnk-python python-registry pefile libfwsi-python regex iocextract oletools"
  for pip_pkg in $sift_pip_pkgs;
  do
    pip3 install $pip_pkg || pause
  done


  #Install Applications from Apt
  sift_apt_pkgs="fdupes sleuthkit attr ewf-tools afflib-tools qemu-utils libbde-utils python3-libesedb exfat-utils libvshadow-utils xmount libesedb-utils liblnk-utils libevtx-utils pff-tools sqlite3"

  for apt_pkg in $sift_apt_pkgs;
  do
    echo "Installing $apt_pkg"
    sudo apt-get install $apt_pkg -y 
    dpkg -S $apt_pkg && echo "$apt_pkg Installed!"|| pause
  done

  #Git and configure Package Installations and Updates

  #Git analyzeMFT
  [ "$(ls -A /usr/local/src/analyzeMFT/ 2>/dev/null)" ] && \
  git -C /usr/local/src/analyzeMFT pull 2>/dev/null|| \
  git clone https://github.com/dkovar/analyzeMFT.git /usr/local/src/analyzeMFT
  [ "$(ls -A /usr/local/src/analyzeMFT/)" ] || pause
  cd /usr/local/src/analyzeMFT/ 
  python2 setup.py install || pause

  #Git IRIT Files
  [ "$(ls -A /usr/local/src/irit/ 2>/dev/null)" ] && \
  git -C /usr/local/src/irit pull 2>/dev/null || \
  git clone https://github.com/siftgrab/irit.git /usr/local/src/irit
  [ "$(ls -A /usr/local/src/irit/)" ] && chmod 755 /usr/local/src/irit/* || pause

  #Git and configure Harlan Carvey tools
  [ "$(ls -A /usr/local/src/keydet89/tools/ 2>/dev/null)" ] && \
  git -C /usr/local/src/keydet89/tools/ pull 2>/dev/null || \
  git clone https://github.com/keydet89/Tools.git /usr/local/src/keydet89/tools/ 
  chmod 755 /usr/local/src/keydet89/tools/source/* || pause
  #set Windows Perl scripts in Keydet89/Tools/source 
  find /usr/local/src/keydet89/tools/source -type f 2>/dev/null|grep pl$ | while read d;
  do
    file_name=$( echo "$d"|sed 's/\/$//'|awk -F"/" '{print $(NF)}')
    sed -i '/^#! c:[\]perl[\]bin[\]perl.exe/d' $d && sed -i "1i #!`which perl`" $d
    cp $d /usr/local/bin/$file_name || pause
  done

  #Git and configure WMI Forensics
  [ "$(ls -A /usr/local/src/WMI_Forensics/ 2>/dev/null)" ] && \
  git -C /usr/local/src/WMI_Forensics pull 2>/dev/null || \
  git clone https://github.com/davidpany/WMI_Forensics.git /usr/local/src/WMI_Forensics
  cp /usr/local/src/WMI_Forensics/CCM_RUA_Finder.py /usr/local/bin/CCM_RUA_Finder.py || pause
  cp /usr/local/src/WMI_Forensics/PyWMIPersistenceFinder.py /usr/local/bin/PyWMIPersistenceFinder.py || pause

  #Git Volatility3
  [ "$(ls -A /usr/local/src/volatility/ 2>/dev/null)" ] && \
  git -C /usr/local/src/volatility pull 2>/dev/null|| \
  git clone https://github.com/volatilityfoundation/volatility3.git /usr/local/src/volatility
  chmod 755  /usr/local/src/volatility/*.py

  #Git kacos200 Scripts
  [ "$(ls -A /usr/local/src/kacos2000/Queries 2>/dev/null)" ] && \
  git -C /usr/local/src/kacos2000/Queries pull 2>/dev/null|| \
  mkdir -p /usr/local/src/kacos2000 \
  git clone https://github.com/kacos2000/Queries.git /usr/local/src/kacos2000/Queries

  [ "$(ls -A /usr/local/src/kacos2000/WindowsTimeline 2>/dev/null)" ] && \
  git -C /usr/local/src/kacos2000/WindowsTimeline pull 2>/dev/null|| \
  mkdir -p /usr/local/src/kacos2000
  git clone https://github.com/kacos2000/WindowsTimeline.git /usr/local/src/kacos2000/WindowsTimeline

  # Use Wget to download files
  #Download MFT_dump
  mkdir -p /usr/local/src/mft_dump
  curl -s https://api.github.com/repos/omerbenamram/mft/releases/latest| \
  grep -E 'browser_download_url.*unknown-linux-gnu.tar.gz'|awk -F'"' '{system("wget -P /tmp "$4) }' && \
  tar -xvf /tmp/mft*.gz -C /usr/local/src/
  chmod 755 /usr/local/src/mft_dump/mft_dump && cp /usr/local/src/mft_dump/mft_dump /usr/local/bin/ || pause

  #git lf File Browser
  curl -s https://api.github.com/repos/gokcehan/lf/releases/latest | \
  grep browser_download_url | grep lf-linux-amd64.tar.gz | \
  awk -F'"' '{system("wget -P /tmp "$4) }' && \
  tar -xvf /tmp/lf-linux*.gz -C /tmp
  chmod 755 /tmp/lf && cp /tmp/lf /usr/local/bin/lf || pause

  # Download Siftgrab Tools
  mkdir -p /usr/local/src/siftgrab
  wget -O /usr/local/src/siftgrab/ermount.sh https://raw.githubusercontent.com/siftgrab/EverReady-Disk-Mount/master/ermount.sh || pause 
  wget -O /usr/local/src/siftgrab/prefetchruncounts.py https://raw.githubusercontent.com/siftgrab/prefetchruncounts/master/prefetchruncounts.py || pause 
  wget -O /usr/local/src/siftgrab/winservices.py https://raw.githubusercontent.com/siftgrab/Python-Registry-Extraction/master/winservices.py || pause 
  wget -O /usr/local/src/siftgrab/RegRipper30-apt-git-Install.sh https://raw.githubusercontent.com/siftgrab/siftgrab/master/regripper.conf/RegRipper30-apt-git-Install.sh  || pause
  wget -O /usr/local/src/siftgrab/parse_evtx_tasks.py  https://raw.githubusercontent.com/siftgrab/WindowsEventLogs/master/parse_evtx_tasks.py || pause
  wget -O /usr/local/src/siftgrab/parse_evtx_tasks.py  https://raw.githubusercontent.com/siftgrab/WindowsEventLogs/master/parse_evtx_tasks.py || pause
  wget -O /usr/local/src/siftgrab/parse_evtx_tasks.py  https://raw.githubusercontent.com/siftgrab/WindowsEventLogs/master/parse_evtx_tasks.py || pause
  wget -O /usr/local/src/siftgrab/parse_evtx_BITS.py  https://raw.githubusercontent.com/siftgrab/WindowsEventLogs/master/parse_evtx_BITS.py || pause
  chmod -R 755 /usr/local/src/siftgrab/*  || pause 
  [ -f "/usr/local/bin/siftgrab.sh" ]  || cp /usr/local/src/irit/siftgrab.sh /usr/local/bin/siftgrab || pause 
  [ -f "/usr/local/bin/ermount" ]  ||cp /usr/local/src/siftgrab/ermount.sh /usr/local/bin/ermount || pause 
  [ -f "/usr/local/bin/prefetchruncounts.py" ] || cp /usr/local/src/siftgrab/prefetchruncounts.py /usr/local/bin/prefetchruncounts.py || pause 
  [ -f "/usr/local/bin/winservices.py" ] || cp /usr/local/src/siftgrab/winservices.py /usr/local/bin/winservices.py || pause 

  #install RegRipper.git and RegRipper install script
  /usr/local/src/siftgrab/RegRipper30-apt-git-Install.sh

  # Get Job Parser
  wget -O /usr/local/src/irit/jobparser.py https://raw.githubusercontent.com/gleeda/misc-scripts/master/misc_python/jobparser.py || pause
  mv /usr/local/src/irit/jobparser.py /usr/local/bin/

  #Create a symbolic link to /opt/share
  [ -d "/opt/share" ] || ln -s /usr/local/src/ /opt/share
}

function add_tools(){
  # Extended Tools Install
  #Install tools from apt
  extended_aptpkgs="jq gparted feh yara gddrescue rar unrar p7zip-full p7zip-rar python-jinja2 stegosuite clamav clamtk gridsite-clients foremost testdisk graphviz ifuse"
  for apt_pkg in $extended_aptpkgs;
  do
    echo "Installing $apt_pkg"
    sudo apt-get install $apt_pkg -y 
    dpkg -S $apt_pkg && echo "$apt_pkg Installed!"|| pause
  done
  
  # Install Powershell
  pwsh -v || install_powershell
  
  #TO DO
  #Install Hindsight and Unfurl
  #pip3 install pytz puremagic pyhindsight || pause 
  #pip3 install dfir-unfurl -U || pause 

  # Install from git
  # git bulk extractor
  [ "$(ls -A /usr/local/src/bulk_extractor/)" ] && \
  git -C /usr/local/src/bulk_extractor pull 2>/dev/null|| \ 
  git clone https://github.com/simsong/bulk_extractor.git /usr/local/src/bulk_extractor 
  # Requires a manual install bulk extractor

  #Git and configure INDXParse
  [ "$(ls -A /usr/local/src/INDXParse/)" ] && \
  git -C /usr/local/src/INDXParse pull 2>/dev/null||\
  git clone https://github.com/williballenthin/INDXParse.git /usr/local/src/INDXParse

  #Git and configure Didier Stevens Tools
  [ "$(ls -A /usr/local/src/DidierStevensSuite/)" ] && \
  git -C /usr/local/src/DidierStevensSuite pull 2>/dev/null|| \
  git clone https://github.com/DidierStevens/DidierStevensSuite.git /usr/local/src/DidierStevensSuite

  #Git Yara Rules
  [ "$(ls -A /usr/local/src/yara/Neo23x0/signature-base/)" ] && \
  git -C /usr/local/src/yara/Neo23x0/signature-base pull|| \
  git clone https://github.com/Neo23x0/signature-base.git /usr/local/src/yara/Neo23x0/signature-base
  [ "$(ls -A /usr/local/src/yara/reversinglabs/)" ] && \
  git -C /usr/local/src/yara/reversinglabs pull 2>/dev/null|| \
  git clone https://github.com/reversinglabs/reversinglabs-yara-rules.git /usr/local/src/yara/reversinglabs
  [ "$(ls -A /usr/local/src/yara/yararules.com/)" ] && \
  git -C /usr/local/src/yara/yararules.com pull 2>/dev/null|| \
  git clone https://github.com/Yara-Rules/rules.git /usr/local/src/yara/yararules.com

  #Git LogFileParser
  [ "$(ls -A /usr/local/src/LogFileParser/)" ] && \
  git -C /usr/local/src/LogFileParser pull|| \
  git clone https://github.com/jschicht/LogFileParser.git /usr/local/src/LogFileParser

  [ "$(ls -A /usr/local/src/cugu/afro )" ] && \
  git -C /usr/local/src/cugu/afro || \
  git clone https://github.com/cugu/afro.git /usr/local/src/cugu/afro

  # Get Floss
  curl -s https://api.github.com/repos/fireeye/flare-floss/releases/latest | \
  grep -E 'browser_download_url'| grep linux.zip |\
  awk -F'"' '{system("wget -P /tmp "$4) }' && \
  unzip -o /tmp/floss*linux.zip -d /tmp/
  chmod 755 /tmp/floss && cp /tmp/floss /usr/local/bin/floss || pause

  # Get Density Scout
  wget -O /tmp/densityscout_build_45_linux.zip https://cert.at/media/files/downloads/software/densityscout/files/densityscout_build_45_linux.zip || pause
  unzip -o /tmp/densityscout_build_45_linux.zip -d /tmp/densityscout/
  chmod 755 /tmp/densityscout/lin64/densityscout && cp /tmp/densityscout/lin64/densityscout /usr/local/bin/
  # Get ftkimager
  wget  https://ad-zip.s3.amazonaws.com/ftkimager.3.1.1_ubuntu64.tar.gz -O - | tar -xzvf - -C /usr/local/src/irit/
  chmod -755 /usr/local/src/irit/ftkimager && mv /usr/local/src/irit/ftkimager /usr/local/bin/  || pause

  #Get DeXRAY
  wget -O /usr/local/src/irit/DeXRAY.pl http://hexacorn.com/d/DeXRAY.pl
  chmod -755 /usr/local/src/irit/DeXRAY.pl && mv /usr/local/src/irit/DeXRAY.pl /usr/local/bin/  || pause

  #Git CyLR
  curl -s https://api.github.com/repos/orlikoski/CyLR/releases/latest | \
  grep browser_download_url | grep CyLR_ | cut -d '"' -f 4| while read d; 
  do 
    wget -P /usr/local/src/CyLR/ $d;
  done
  [ "$(ls -A /usr/local/src/CyLR/)" ] || pause

  #Get CyberChef
  mkdir -p /usr/local/src/CyberChef
  curl -s https://api.github.com/repos/gchq/CyberChef/releases/latest |\
  grep -E 'browser_download_url'|awk -F'"' '{system("wget -P /tmp "$4) }' && \
  unzip -o /tmp/Cyber*.zip -d /usr/local/src/CyberChef
}
	 
#### TODO Finish install script for IRIT Gui
function irit_install(){
  # Create irit user
  users |grep irit$ || echo irit:irit::::/home/irit:/bin/$0 | newusers
  usermod -a -G sudo irit

  #Install SqliteBrowser
  snap install sqlitebrowser

  #PPA 
  add-apt-repository -y ppa:papirus/papirus  || pause

  #Apt Package Installations
  gui_install_apt="papirus-icon-theme dconf* gnome-terminal gnome-shell-extensions gnome-tweaks libreoffice-gnome libreoffice gedit wxhexeditor cifs-utils guymager wine chromium-browser"
  for apt_pkg in $gui_install_apt;
  do
    echo "Installing $apt_pkg"
    sudo apt-get install $apt_pkg -y 
    dpkg -S $apt_pkg && echo "$apt_pkg Installed!"|| pause
  done
  #Download Volatility3 Symbol Files
  wget -O /usr/local/src/volatility/volatility3/symbols/windows.zip https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip || pause
  wget -O /usr/local/src/volatility/volatility3/symbols/mac.zip https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip || pause
  wget -O /usr/local/src/volatility/volatility3/symbols/linux.zip https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip || pause

  cp -r /usr/local/src/irit/config/usr/share/* /usr/share/backgrounds/
  cp -r /usr/local/src/irit/config/etc/* /etc/  
  chmod 644 /usr/share/backgrounds/irit*
  
  # Copy files to /etc/skel
  # Add irit user
  # useradd irit 
  # gsettings set org.gnome.desktop.background picture-uri file:///usr/share/backgrounds/irit-logo-dark_spots_texture_2048x1152.jpg
  #cp /usr/local/src/CyberChef/Cyber*.html 

  #Install Autospy 
  #/usr/local/src/irit/install-autospy-gui.sh

}
[ $(whoami) != "root" ] && echo "Requires Root!" && exit
echo "cpu check"
arch |grep x86_64 || display_usage
[ "$1" == "-h" ] && display_usage
which apt && main_install || display_usage
[ "$1" == "-t" ] && add_tools
[ "$1" == "-i" ] && add_tools && irit_install
updatedb
history -c