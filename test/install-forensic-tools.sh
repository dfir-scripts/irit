#! /bin/bash

function display_usage(){
  clear
  echo "
  install-forensic-tools.sh
  Downloads forensic tools to /usr/local/src
  and fullfills requirements for running siftgrab from a physical system or virtual machine

  USAGE: install-forensic-tools.sh -h

         -h Displays this help text

"
    exit
}

function pause(){
 read -s -n 1 -p "Command failed!!!! Press any key to continue . . ."
 echo ""
}

function install_gift_ppa(){
  apt-get install software-properties-common -y && \
  add-apt-repository ppa:gift/stable -y &&  apt update || pause
  apt upgrade -q -y -u  || pause
  cat /etc/issue|grep -Ei "u 2"\|"u 18" && \
  apt-get install libscca libewf-tools libbde-tools libvshadow-tools libesedb-tools liblnk-tools libevtx-tools plaso-tools bulk-extractor -y
}

function main_install(){
  apt remove libewf2 -y
  apt update 
  apt-get install python3-pip python3*-venv pipx git curl fdisk wget software-properties-common busybox -y
  pipx ensurepath

  cat /etc/issue|grep -i kali && \
  apt-get install gnome-terminal libewf-dev ewf-tools libbde-utils libvshadow-utils libesedb-utils xmount liblnk-utils libevtx-utils python3-libesedb plaso -y

  ############### Forensic Tools Download, Install and Confiuration ##########################
  #Make Disk Mount and Cases Directories
  mkdir -p /mnt/{raw,image_mount,vss,shadow,bde,smb,usb,zip}
  mkdir -p /cases

# setup python virtual environment
  VIRTUAL_ENV=/opt/venv
  python3 -m venv $VIRTUAL_ENV
  PATH="$VIRTUAL_ENV/bin:$PATH"
  source activate || pause

  #pip installs
  sift_pip_pkgs="registryspy psutil prefetchcarve usncarve LnkParse3 usnparser tabulate puremagic construct libesedb-python==20181229 openpyxl>=2.6.2 pefile>=2019.4.18 python-registry>=1.3.1 pywin32-ctypes>=0.2.0 six>=1.12.0 bits_parser pyarrow evtxtract beautifulsoup4 libscca-python setuptools==58.2.0 python-evtx regex oletools pandas sqlalchemy gdown"
  for pip_pkg in $sift_pip_pkgs;
  do
    pip3 install $pip_pkg || pause
  done

  #Install yarp
  git_release="https://github.com/msuhanov/yarp/releases/"
  git_download="https://github.com/msuhanov/yarp/archive"
  latest_ver=$(curl -s "$git_release" |grep -Po -m 1 '(?<=tag/).*(?=" data)')
  pip3 install $git_download/$latest_ver.tar.gz

  #Install dfir_ntfs
  git_release="https://github.com/msuhanov/dfir_ntfs/releases/"
  git_download="https://github.com/msuhanov/dfir_ntfs/archive"
  latest_ver=$(curl -s "$git_release" |grep -Po -m 1 '(?<=tag/).*(?=" data)')
  pip3 install $git_download/$latest_ver.tar.gz

  #Install Gift PPA
  install_gift_ppa
  #Install Applications from Apt
  sift_apt_pkgs="hashid cifs-utils fdupes sleuthkit attr dcfldd afflib-tools autopsy qemu-utils lvm2 exfatprogs kpartx pigz exif dc3dd pff-tools python-is-python3 python3-lxml sqlite3 jq yara unzip p7zip-full p7zip-rar hashcat foremost caffeine parallel fuse-zip testdisk chntpw graphviz ffmpeg mediainfo ifuse clamav geoip-bin geoip-database geoipupdate libsnappy-dev gnumeric xxd reglookup ripgrep vinetto fd-find"
  for apt_pkg in $sift_apt_pkgs;
  do
    echo "Installing $apt_pkg"
    apt-get install $apt_pkg -y
    dpkg -S $apt_pkg && echo "$apt_pkg Installed!"|| pause
  done

  #Git and configure Package Installations and Updates
  #Git analyzeMFT
  [ "$(ls -A /usr/local/src/analyzeMFT/ 2>/dev/null)" ] && \
  cd /usr/local/src/analyzeMFT
  git -C /usr/local/src/analyzeMFT pull --force 2>/dev/null|| \
  git clone https://github.com/dkovar/analyzeMFT.git /usr/local/src/analyzeMFT
  [ "$(ls -A /usr/local/src/analyzeMFT/)" ] || pause
  cd /usr/local/src/analyzeMFT/
  git checkout 16d12822563cd5cae8675788134ac0ff6e9f5c01

  #Git BitsParser
  [ "$(ls -A /usr/local/src/BitsParser)" ] && \
  git -C /usr/local/src/BitsParser pull --force 2>/dev/null || \
  git clone https://github.com/fireeye/BitsParser.git /usr/local/src/BitsParser
  
  #Git DFIR-Scripts Siftgrab
  [ "$(ls -A /usr/local/src/dfir-scripts/siftgrab 2>/dev/null)" ] && \
  git -C /usr/local/src/dfir-scripts/siftgrab pull --force 2>/dev/null || \
  git clone https://github.com/dfir-scripts/siftgrab.git /usr/local/src/dfir-scripts/siftgrab
  [ "$(ls -A /usr/local/src/dfir-scripts/siftgrab)" ] && chmod -R 755 /usr/local/src/dfir-scripts/siftgrab/* || pause

  #Git DFIR-Script shell scripts
  [ "$(ls -A /usr/local/src/dfir-scripts/shellscripts 2>/dev/null)" ] && \
  git -C /usr/local/src/dfir-scripts/shellscripts pull --force 2>/dev/null || \
  git clone https://github.com/dfir-scripts/shellscripts.git /usr/local/src/dfir-scripts/shellscripts
  [ "$(ls -A /usr/local/src/dfir-scripts/shellscripts)" ] && chmod 755 /usr/local/src/dfir-scripts/shellscripts/* || pause

  #Git DFIR-Scripts ermount
  [ "$(ls -A /usr/local/src/dfir-scripts/ermount 2>/dev/null)" ] && \
  git -C /usr/local/src/dfir-scripts/ermount pull --force 2>/dev/null || \
  git clone https://github.com/dfir-scripts/EverReady-Disk-Mount.git /usr/local/src/dfir-scripts/ermount
  [ "$(ls -A /usr/local/src/dfir-scripts/ermount)" ] && chmod -R 755 /usr/local/src/dfir-scripts/ermount/* || pause
  
  #Git DFIR-Scripts Eventlog parsers
  [ "$(ls -A /usr/local/src/dfir-scripts/WinEventLogs 2>/dev/null)" ] && \
  git -C /usr/local/src/dfir-scripts/WinEventLogs pull --force 2>/dev/null || \
  git clone https://github.com/dfir-scripts/WinEventLogs.git /usr/local/src/dfir-scripts/WinEventLogs
  [ "$(ls -A /usr/local/src/dfir-scripts/WinEventLogs)" ] && chmod -R 755 /usr/local/src/dfir-scripts/WinEventLogs/* || pause

  #Git DFIR-Scripts Installer
  [ "$(ls -A /usr/local/src/dfir-scripts/installers 2>/dev/null)" ] && \
  git -C /usr/local/src/dfir-scripts/installers pull --force 2>/dev/null || \
  git clone https://github.com/dfir-scripts/installers.git /usr/local/src/dfir-scripts/installers
  [ "$(ls -A /usr/local/src/dfir-scripts/installers)" ] && chmod -R 755 /usr/local/src/dfir-scripts/installers || pause

  #Git DFIR-Scripts Prefetchruncounts
  [ "$(ls -A /usr/local/src/dfir-scripts/prefetchruncounts 2>/dev/null)" ] && \
  git -C /usr/local/src/dfir-scripts/prefetchruncounts pull --force 2>/dev/null || \
  git clone https://github.com/dfir-scripts/prefetchruncounts.git /usr/local/src/dfir-scripts/prefetchruncounts
  [ "$(ls -A /usr/local/src/dfir-scripts/prefetchruncounts)" ] && chmod -R 755 /usr/local/src/dfir-scripts/prefetchruncounts || pause

  #Git DFIR-Scripts Python-Registry
  [ "$(ls -A /usr/local/src/dfir-scripts/Python-Registry 2>/dev/null)" ] && \
  git -C /usr/local/src/dfir-scripts/Python-Registry pull --force 2>/dev/null || \
  git clone https://github.com/dfir-scripts/Python-Registry.git /usr/local/src/dfir-scripts/Python-Registry
  [ "$(ls -A /usr/local/src/dfir-scripts/Python-Registry)" ] && chmod -R 755 /usr/local/src/dfir-scripts/Python-Registry || pause  

  #Git DFIR-Scripts csv2XLsheet
  [ "$(ls -A /usr/local/src/dfir-scripts/csv2XLsheet 2>/dev/null)" ] && \
  git -C /usr/local/src/dfir-scripts/csv2XLsheet pull --force 2>/dev/null || \
  git clone https://github.com/dfir-scripts/csv2XLsheet.git /usr/local/src/dfir-scripts/csv2XLsheet
  [ "$(ls -A /usr/local/src/dfir-scripts/csv2XLsheet)" ] && chmod -R 755 /usr/local/src/dfir-scripts/csv2XLsheet || pause

    #Git DFIR-Scripts lnk2j
  [ "$(ls -A /usr/local/src/dfir-scripts/lnk2j 2>/dev/null)" ] && \
  git -C /usr/local/src/dfir-scripts/lnk2j pull --force 2>/dev/null || \
  git clone https://github.com/dfir-scripts/lnk2j.git /usr/local/src/dfir-scripts/lnk2j
  [ "$(ls -A /usr/local/src/dfir-scripts/lnk2j)" ] && chmod -R 755 /usr/local/src/dfir-scripts/lnk2j/lnk2j.py || pause
  cp /usr/local/src/dfir-scripts/lnk2j/lnk2j.py /opt/venv/bin/lnk2j.py

  #Git Volatility3
  [ "$(ls -A /usr/local/src/volatility/ 2>/dev/null)" ] && \
  git -C /usr/local/src/volatility pull --force 2>/dev/null|| \
  git clone https://github.com/volatilityfoundation/volatility3.git /usr/local/src/volatility3

  #Git kacos2000 Scripts
  [ "$(ls -A /usr/local/src/kacos2000/Queries 2>/dev/null)" ] && \
  git -C /usr/local/src/kacos2000/Queries pull --force 2>/dev/null|| \
  git clone https://github.com/kacos2000/Queries.git /usr/local/src/kacos2000/Queries

  [ "$(ls -A /usr/local/src/kacos2000/WindowsTimeline 2>/dev/null)" ] && \
  git -C /usr/local/src/kacos2000/WindowsTimeline pull --force 2>/dev/null|| \
  git clone https://github.com/kacos2000/WindowsTimeline.git /usr/local/src/kacos2000/WindowsTimeline

  #Git and configure Didier Stevens Tools
  [ "$(ls -A /usr/local/src/DidierStevensSuite/)" ] && \
  git -C /usr/local/src/DidierStevensSuite pull --force 2>/dev/null|| \
  git clone https://github.com/DidierStevens/DidierStevensSuite.git /usr/local/src/DidierStevensSuite

  #Git Kstrike
  [ "$(ls -A /usr/local/src/KStrike)" ] && \
  git -C /usr/local/src/KStrike pull --force 2>/dev/null|| \
  git clone https://github.com/brimorlabs/KStrike.git /usr/local/src/KStrike

  #Git Srum-Dump
  [ "$(ls -A /usr/local/src/srum-dump)" ] && \
  git -C /usr/local/src/srum-dump pull --force 2>/dev/null|| \
  git clone https://github.com/dfir-scripts/srum-dump.git /usr/local/src/srum-dump
  pip3 install -qr /usr/local/src/srum-dump/requirements.txt

  #Git Zircolite
  [ "$(ls -A /usr/local/src/Zircolite)" ] && \
  git -C /usr/local/src/Zircolite pull --force 2>/dev/null || \
  git clone https://github.com/wagga40/Zircolite.git /usr/local/src/Zircolite
  pip3 install -r /usr/local/src/Zircolite/requirements.full.txt

  #Git EventTranscriptParser
  [ "$(ls -A /usr/local/src/EventTranscriptParser)" ] && \
  git -C /usr/local/src/EventTranscriptParser pull --force 2>/dev/null || \
  git clone https://github.com/stuxnet999/EventTranscriptParser.git /usr/local/src/EventTranscriptParser

  #Git RegistryFlush
  [ "$(ls -A /usr/local/src/Silv3rHorn)" ] && \
  git -C /usr/local/src/Silv3rhorn pull --force 2>/dev/null || \
  git clone https://github.com/dfir-scripts/4n6_misc.git /usr/local/src/Silv3rhorn
  cp /usr/local/src/Silv3rhorn/*.py /opt/venv/bin/
  chmod 755 /opt/venv/bin/registryFlush.py

  #Git Python-Registry
  [ "$(ls -A /usr/local/src/Python-Registry)" ] && \
  git -C /usr/local/src/Python-Registry pull --force 2>/dev/null || \
  git clone https://github.com/williballenthin/python-registry.git /usr/local/src/Python-Registry
  
    #Git BMC-Tools
  [ "$(ls -A /usr/local/src/BMC-Tools)" ] && \
  git -C /usr/local/src/BMC-Tools pull --force 2>/dev/null || \
  git clone https://github.com/ANSSI-FR/bmc-tools.git /usr/local/src/BMC-Tools
  
  #Git and configure Harlan Carvey tools
  [ "$(ls -A /usr/local/src/keydet89/tools/ 2>/dev/null)" ] && \
  git -C /usr/local/src/keydet89/tools/ pull --force 2>/dev/null || \
  git clone https://github.com/keydet89/Tools.git /usr/local/src/keydet89/tools/
  chmod 755 /usr/local/src/keydet89/tools/source/* || pause

  #Alternative python module installs 
  PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install impacket
  pip install pyhindsight==20230327.0
  
  chmod 755 /opt/venv/bin/hindsight.py
  chmod 755 /opt/venv/bin/hindsight_gui.py

  #Download evtx_dump
  mkdir -p /usr/local/src/omerbenamram/evtx_dump/
  git_release="https://api.github.com/repos/omerbenamram/evtx/releases/latest"
  install_dir="/usr/local/src/omerbenamram/evtx_dump"
  current_ver=$($install_dir/evtx_dump -V 2>/dev/null|sed 's/.* /v/')
  latest_ver=$(curl -s "$git_release" | grep -Po '"tag_name": "\K.*?(?=")')
  [ $current_ver ] && updated_status=$(echo -e "$current_ver\n$latest_ver" |sort -V |grep -m 1 $current_ver )
  [ $updated_status ] || curl -s $git_release | \
  grep -E 'browser_download_url.*64-unknown-linux-musl'| \
  awk -F'"' '{system("wget -O /usr/local/src/omerbenamram/evtx_dump/evtx_dump "$4) }'  && \
  chmod 755 $install_dir/evtx_dump && cp $install_dir/evtx_dump /usr/local/bin/evtx_dump || pause

  # Use Wget and curl to download tools
  #Download mft_dump
  mkdir -p /usr/local/src/omerbenamram/mft_dump/
  git_release="https://api.github.com/repos/omerbenamram/mft/releases/latest"
  install_dir="/usr/local/src/omerbenamram/mft_dump"
  current_ver=$($install_dir/mft_dump -V 2>/dev/null|sed 's/.* /v/')
  latest_ver=$(curl -s "$git_release" | grep -Po '"tag_name": "\K.*?(?=")')
  [ $current_ver ] && updated_status=$(echo -e "$current_ver\n$latest_ver" |sort -V |grep -m 1 $current_ver )
  [ $updated_status ] || curl -s $git_release | \
  grep -E 'browser_download_url.*64-unknown-linux-musl'| \
  awk -F'"' '{system("wget -O /usr/local/src/omerbenamram/mft_dump/mft_dump "$4) }'  && \
  chmod 755 $install_dir/mft_dump && cp $install_dir/mft_dump /usr/local/bin/mft_dump || pause

  #Download Haybusa
  mkdir -p /usr/local/src/Hayabusa
  cd /usr/local/src/Hayabusa
  current_ver=$(hayabusa help 2>/dev/null |head -n 1|awk '{print $2}' 2>/dev/null)
  latest_ver=$(curl -s https://github.com/Yamato-Security/hayabusa/ |grep -Po "(?<=tag/v)[^\">]+")
  [ $current_ver == $latest_ver ] && echo "already updated" || \
  wget -qO - https://github.com/Yamato-Security/hayabusa/releases/download/v$latest_ver/hayabusa-$latest_ver-all-platforms.zip| busybox unzip -
  cp hayabusa-*-lin-x64-musl /usr/local/bin/hayabusa 2>/dev/null
  chmod 755 /usr/local/bin/hayabusa
  
  #Install Ntdissector
  mkdir -p /usr/local/src/Ntdissector
  cd /usr/local/src/
  [ -d /opt/app/Ntdissector/ntdissector ] || git clone https://github.com/synacktiv/ntdissector.git Ntdissector
  python3 -m pip install ./Ntdissector

  #Download Event Hussar
  wget -qO - https://github.com/yarox24/EvtxHussar/releases/download/1.8/EvtxHussar1.8_linux_amd64.zip |busybox unzip - -d /usr/local/src/
  chmod 755 /usr/local/src/EvtxHussar/EvtxHussar

#Download lf File Browser
  curl -s https://api.github.com/repos/gokcehan/lf/releases/latest | \
  grep browser_download_url | grep lf-linux-amd64.tar.gz | \
  awk -F'"' '{system("wget -P /tmp "$4) }' && \
  tar -xvf /tmp/lf-linux*.gz -C /tmp
  chmod 755 /tmp/lf && mv /tmp/lf /usr/local/bin/lf || pause

  # Download Density Scout
  wget -qO - https://cert.at/media/files/downloads/software/densityscout/files/densityscout_build_45_linux.zip| \
  busybox unzip -j - lin64/densityscout -d /usr/local/src/dfir-scripts/ && \
  mv /usr/local/src/dfir-scripts/densityscout /usr/local/bin/densityscout && \
  chmod 755 /usr/local/bin/densityscout

  #wget winmem_decompress
  wget -O /usr/local/bin/winmem_decompress.py https://raw.githubusercontent.com/msuhanov/winmem_decompress/master/winmem_decompress.py
  chmod 755 /usr/local/bin/winmem_decompress.py

#Download lf File Browser
  curl -s https://api.github.com/repos/gokcehan/lf/releases/latest | \
  grep browser_download_url | grep lf-linux-amd64.tar.gz | \
  awk -F'"' '{system("wget -P /tmp "$4) }' && \
  tar -xvf /tmp/lf-linux*.gz -C /tmp
  chmod 755 /tmp/lf && mv /tmp/lf /usr/local/bin/lf
  rm /tmp/lf-linux*.gz

  # Download lolbas.csv
  mkdir -p /usr/local/src/keywords
  wget -O /usr/local/src/keywords/lolbas.csv https://lolbas-project.github.io/api/lolbas.csv
  cat /usr/local/src/keywords/lolbas.csv |awk -F'"' '{print $2}'|sort -u |tee /usr/local/src/keywords/lolbas-files.txt
  [ "$(ls -A /usr/local/src/keywords/ThreatHunting-Keywords-yara-rules/ 2>/dev/null)" ] && \
  git -C /usr/local/src/ThreatHunting-Keywords-yara-rules pull --force 2>/dev/null || \
  git clone https://github.com/mthcht/ThreatHunting-Keywords-yara-rules.git /usr/local/src/keywords/ThreatHunting-Keywords-yara-rules/

  wget -O /usr/local/src/keywords/only_keywords_regex.txt https://raw.githubusercontent.com/mthcht/ThreatHunting-Keywords/main/only_keywords_regex.txt
  wget -O /usr/local/src/keywords/only_keywords_regex_better_perf.txt https://raw.githubusercontent.com/mthcht/ThreatHunting-Keywords/main/only_keywords_regex_better_perf.txt
  wget -O /usr/local/src/keywords/all.yara https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/raw/refs/heads/main/yara_rules/all.yara
  vi -c ":set nobomb" -c ":wq" /usr/local/src/keywords/only_keywords_regex.txt
  vi -c ":set nobomb" -c ":wq" /usr/local/src/keywords/only_keywords_regex_better_perf.txt

  # Download Jumplist APPIDs
  mkdir -p /usr/local/src/EricZimmerman
  wget -O /usr/local/src/EricZimmerman/AppIDs.txt https://raw.githubusercontent.com/EricZimmerman/JumpList/master/JumpList/Resources/AppIDs.txt

  # Convert AppIDs to csv for JLParser
  cat /usr/local/src/EricZimmerman/AppIDs.txt | awk -F'"' '{print "Application IDs,"tolower($2)","$4}' >> /usr/local/src/EricZimmerman/AppIDs.csv

  # Get mount that thing
  wget -O /usr/local/bin/mtt https://raw.githubusercontent.com/halpomeranz/dfis/refs/heads/master/mtt.sh
  chmod 755 /usr/local/bin/mtt
  
  #  Get compiled version of Sidr
  wget -O /usr/local/bin/sidr https://github.com/dfir-scripts/sidr/raw/refs/heads/main/sidr || pause
  chmod 755 /usr/local/bin/sidr

  # Download MemProcFS
  rm -r /usr/local/src/MemProcFS/ 2>/dev/null
  mkdir -p /usr/local/src/MemProcFS
  cd /usr/local/src/MemProcFS
  curl -s "https://api.github.com/repos/ufrisk/MemProcFS/releases/latest" | \
  jq -r '.assets[] | .browser_download_url' |grep linux_x64| xargs curl -LO
  ls -A && tar -xvf /usr/local/src/MemProcFS/*.gz -C  /usr/local/src/MemProcFS/ && \
  rm /usr/local/src/MemProcFS/*.gz

  chmod -R 755 /usr/local/src/dfir-scripts/*  || pause
  cp /usr/local/src/dfir-scripts/siftgrab/siftgrab /usr/local/bin/siftgrab || pause
  cp /usr/local/src/dfir-scripts/ermount/ermount.sh /usr/local/bin/ermount || pause

  #install RegRipper.git and RegRipper install script
  /usr/local/src/dfir-scripts/installers/RegRipper30-apt-git-Install.sh

  #Create a symbolic links to /opt/share and for fd
  [ -d "/opt/app" ] || ln -s /usr/local/src/ /opt/app
  ln -s $(which fdfind) /usr/local/bin/fd
  #set Windows Perl scripts in Keydet89/Tools/source
  find /usr/local/src/keydet89/tools/source -type f 2>/dev/null|grep pl$ | while read d;
  do
    a=$(which perl)
    file_name=$( echo "$d"|sed 's/\/$//'|awk -F"/" '{print $(NF)}')
    sed -i '/^#! c:[\]perl[\]bin[\]perl.exe/d' $d && sed -i "1i #!$a" $d
    cp $d /usr/local/bin/$file_name || pause
  done
  
wget -O /tmp/setup-zimmerman-tools.sh https://gist.githubusercontent.com/dfir-scripts/10034ce77b04db988dcafbbb2567a426/raw/setup-zimmerman-tools.sh
chmod 755 /tmp/setup-zimmerman-tools.sh
/tmp/setup-zimmerman-tools.sh
rm /tmp/setup-zimmerman-tools.sh
cd /opt/zimmermantools
/opt/venv/bin/gdown 1qfiqzv3geQNYsr6R8sZaWPl7nO6NlLeu
unzip -o Zimmerman-linux.zip
chmod 755 WxTCmd/WxTCmd
chmod 755 SQLECmd/SQLECmd
find /opt/zimmermantools/Zimmerman-linux.zip -delete
deactivate
}


[ $(whoami) != "root" ] && echo "Requires Root!" && exit
echo "cpu check"
DEBIAN_FRONTEND=noninteractive
arch |grep x86_64 || display_usage
[ "$1" == "-h" ] && display_usage
which apt && apt update || pause
which apt && main_install
history -c
echo ""
cat /etc/issue|grep -i kali && \
echo "*****************************************" && \
echo "To disable disk automount:" && \
echo "set org.gnome.desktop.media-handling automount false"

echo ""
echo  "   Install Complete!"