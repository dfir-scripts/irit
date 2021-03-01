#!/bin/bash
export TZ='Etc/UTC'
function read_me(){
echo "
##################################################################################

SIFTGRAB
A collection of Open source forensic scripts wrapped into a shell menu that extracts Windows forensic metadata and creates a TLN timeline.
Previous version works on Sans Sift, the new version can be installed installed on systems that use the Apt pacackage manger.
Tested on Ubuntu 20.04, Sift and Kali but should work on any system using the Apt package manager.

Features:
Mounts most image types (Raw, E01, Aff. VMDK, qcow, VHDX)

Extracts the following metadata from mounted images or image exerpts (e.g. Kape, Cylr).

Regripper
....All TLN plugins
....NTUSER.DAT (All Plugins)
....SAM (All Plugins)
....Security (All Plugins)
....AmCache.hve

TLN Timeline
....Regripper (All TLN plugins)
....$MFT
....$USNJRNL
....Chrome
....Firefox
....RecycleBin
....ADS
....LNK Files
....AmCache
....Services
....Prefetch
....Usrclass.dat
....Index.dat
....Chrome
....Firefox
....RecyleBin
....ADS

Acquires Windows files with forensic metata from Mounted images

Additional output from siftgrab
....Windows Activities
....PyWmipersistence finder output
....SCCM Recently Used Application
....lnkinfo

TOOLS included in Siftgrab install:
sleuthkit
Volatility 3
AnalyzeMFT.py
pffexport
usnparser
oletools
pefile
INDXParse
CYLR
WMIForensics
kacos2000/Queries
kacos2000/WindowsTimeline

other scripts:
prefetchruncounts.py
winservices.py
usn.py
MFTINDX.py (Script in INDXParse used to find deleted files in $MFT)
PyWMIPersistencefinder.py
CCM_RUAfinder

other packages:
python2 and python3
liblnk-python
python-registry
libfwsi-python
pycrypto
yara-python
capstone
yara
open-vm-tools-desktop
gedit
mlocate
gparted
attr
gridsite-clients
ewf-tools
afflib-tools
qemu-utils
libbde-utils
exfat-utils
libvshadow-utils
xmount
cifs-utils
guymager
libesedb-utils
liblnk-utils
sqlitebrowser
foremost
testdisk
ifuse
python-wxtools
libevtx-utils
pff-tools
python-jinja2
clamav
clamtk
rar
unrar
p7zip-full
p7zip-rar
papirus-icon-theme
wine
sqlite3
npm
################################################################################
"
}
#Function to produce Red Text Color
function makered() {
    COLOR='\033[01;31m' # bold red
    RESET='\033[00;00m' # normal white
    MESSAGE=${@:-"${RESET}Error: No message passed"}
    echo -e "${COLOR}${MESSAGE}${RESET}"
}
#Function to produce Green Text Color
function makegreen() {
    COLOR='\033[0;32m' # Green
    RESET='\033[00;00m' # normal white
    MESSAGE=${@:-"${RESET}Error: No message passed"}
    echo -e "${COLOR}${MESSAGE}${RESET}"
}
# reusable interactive yes-no function
function yes-no(){
      read -p "(Y/N)?"
      [ "$(echo $REPLY | tr [:upper:] [:lower:])" == "y" ] &&  yes_no="yes";
}
##  Main Siftgrab Display Menu Function
echo ""
function show_menu(){
    GRAY=`echo "\033[0;37m"`
    GREEN=`echo "\033[0;32m"`
    NORMAL=`echo "\033[m"`
    RED=`echo "\033[31m"`
    echo -e "${GREEN}  Siftgrab${NORMAL}"
    echo -e "*****************************************************"
    echo -e "${GRAY}Mount and Extract Information From Windows Disk Images${NORMAL}"
    echo -e "*****************************************************"
    echo -e "**  1) ${GREEN} Mount a Disk Image ( E01, Raw, AFF, QCOW VMDK, VHDX)${NORMAL}"
    echo -e "**  2)${GREEN}  Process Windows Artifacts from Mounted Image or Offline Files${NORMAL}"
    echo -e "**  3)${GREEN}  Extract Windows Event Logs${NORMAL}"
    echo -e "**  4) ${GREEN} Acquire Windows Forensic Artifacts from Mounted Image(s)${NORMAL}"
    echo -e "**  5) ${GREEN} Find and Acquire Volatile Data Files${NORMAL}"
    echo -e "**     ${GREEN} (hiberfil.sys, pagefile, swapfile.sys,)${NORMAL}"
    echo -e "**  6) ${GREEN} Extract Outlook OST/PST Mail Files ${NORMAL}"
    echo -e "**  7) ${GREEN} Browse Files (lf)${NORMAL}"
    echo -e "**  8) ${GREEN} Readme${NORMAL}"
    echo ""
    echo -e "Select a menu option number or ${RED}enter to exit. ${NORMAL}"
    read opt
while [ opt != '' ]
    do
    if [[ $opt = "" ]]; then
            exit;
    else
        case $opt in
        #Menu Selection 1: Mount disk image to $mount_dir
        1) clear;
        *********************
        ###### COMMAND EXECUTION #############
           clear
           #Get drive status and process any cli parameters
           [ -e "/mnt/raw" ] || mkdir -p /mnt/raw
           mount_status
           umount_all
           echo $mount_stat && echo $raw_stat && echo $nbd_stat && echo $vss_stat && echo $vsc_stat && echo $bde_stat && \
           echo "" && echo "Physical Disks: /dev/sd<n>" && lsblk -f /dev/sd* && echo ""
           # Use ermount to mount bitlocker  encrypted files
           # start mounting process and select source image and mount point
           makegreen "ERMount a disk, disk image or VM"
           image_source
           mount_point
           # Send to mounting function based on image type
           [ -f "$image_name"002"" ] &&  echo $multi "Multiple raw disk segments detected, mounting with affuse" && mount_aff
           echo $image_type | grep -qie "AFF$" && mount_aff
           echo $image_type | grep -ie "E01$\|S01" && mount_e01
           echo $image_type | grep -ie "VMDK$\|VDI$\|QCOW2$\|VHD$\|VHDX$" && mount_nbd
           # If no image type detected, process as raw
           [ "$image_src" == "" ] && image_src="${ipath}"
           is_device=$(echo "$image_src" | grep -i "/dev/sd")
           [ "${is_device}" != "" ] && [ "${1}" != "-b" ] && lsblk -f /dev/sd* && mount_image
           [ "${is_device}" != "" ] && [ "${1}" == "-b" ] && bit_locker_mount
           # Set image offset if needed
           set_image_offset
           # Decrypt bitlocker if "-b" is specified
           [ "${1}" == "-b" ] && bit_locker_mount
           # mount image and detect any volume shadow copies
           mount_image
           read -n1 -r -p "Press any key..." key
           clear
            show_menu;
            ;;

        #Menu Selection 2: Process Artifacts Collected using RegRipper and other Tools
        2) clear;
           makegreen "Process Artifacts for Triage"
           set_msource_path
           set_windir
           get_computer_name
           set_dsource_path
           check_dsource_path
           create_triage_dir
           get_usnjrlnsize
           yes-no && usn="yes"
           rip_software
           rip_system
           rip_security
           regrip_ntuser_usrclass
           regrip_user_plugins
           regrip_sam
           regrip_amcache.hve
           regrip_syscache.hve_tln
           prefetch_extract
           extract_objects_data
           del_no_result
           lnkinfo
           recbin2tln
           chrome2tln
           firefox2tln
           skype2tln
           ls  /$mount_dir/Users/*/AppData/Local/Microsoft/Windows/WebCache/We* 2>/dev/null && extract_webcacheV
           winservices
           consolidate_timeline
           extract_winactivities
           ls  /$mount_dir/Users/*/AppData/Local/Microsoft/Windows/WebCache/We* 2>/dev/null || parse_index.dat
           cp_setupapi
           extract_Jobs
           ADS_extract
           analyze_mft
           [ "$usn" ] && parse_usn
           # Clean-up
           find $case_dir -empty -delete
           makegreen "Removing Duplicates..."
           echo "Please Wait..."
           fdupes -rdN $case_dir
           makegreen "The Processed Artifacts are Located in $case_dir/Triage"
           du -sh $case_dir/Triage
           makegreen Process Complete!
           read -n1 -r -p "Press any key to continue..." key
           show_menu;
            ;;
        #Menu Selection 3: Extract Windows Event Log Files
        3) clear;
           makegreen "Process Event Log Artifacts for Triage"
           set_msource_path
           set_windir
           get_computer_name
           set_dsource_path
           create_triage_dir
           extract_WinEVTX
           # Clean-up
           find $case_dir -empty -delete
           makegreen "Removing Duplicates..."
           echo "Please Wait..."
           fdupes -rdN $case_dir
           makegreen "The Processed Artifacts are Located in $case_dir/Triage"
           du -sh $case_dir/Triage
           makegreen Process Complete!
           read -n1 -r -p "Press any key to continue..." key
           show_menu;
            ;;
        #Menu Selection 4: Acquire Data from Mounted Disks or Image Excerpts
        4) clear;
           # Set Preferences
           makegreen "Get a copy of Windows Artifacts"
           set_msource_path
           set_windir
           get_computer_name
           set_dsource_path
           echo "#### Acquistion Log $comp_name  ####" >  $case_dir/Acquisition.log.txt
           get_logsize
           get_usnjrlnsize
           yes-no && get_usnjrnl
           # Begin Acquisition
           echo ""
           get_mft
           get_evtx
           get_registry
           get_ntuser
           get_usrclass.dat
           get_lnk_files
           get_prefetch
           get_Amcache.hve
           get_Recycle.Bin
           get_webcachev
           get_chrome
           get_firefox
           get_skype
           get_WMI_info
           get_srumdb
           get_ActivitiesCache
           get_setupapi
           get_scheduled_tasks
           [ "$get_logs" ] && get_logfiles
           gzip -f $case_dir/$comp_name-acquisition.tar
           makegreen "Data Acquisition Complete!"
           du -sh $case_dir/$comp_name-acquisition.tar.gz
           read -n1 -r -p "Press any key to continue..." key
           clear;
           show_menu;
            ;;
        #Menu Selection 5:  Collect Volatile files from mounted image
        5) clear;
           set_msource_path
           set_dsource_path
           set_windir
           get_computer_name
           makered "COLLECTING VOLITILE FILES (hiberfil.sys, swapfile.sys, pagefile.sys and *.dmp)"
           get_volatile
           read -n1 -r -p "Press any key to continue..." key
           clear;
           show_menu;
            ;;
        #Menu Selection 6: Collect Outlook Email OST/PST files
        6) clear;
           makegreen "Extract Windows PST/OST file"
           set_msource_path
           set_windir
           get_computer_name
           set_dsource_path
           get_computer_name
           create_triage_dir
           extract_Outlook_pst_ost
           find $case_dir -empty -delete
           read -n1 -r -p "Press any key to continue..." key
           makegreen "Complete!!"
           clear;
           show_menu;
            ;;
        #Menu Selection 7:Lf File Browser
        7) clear;
           cd /cases
           gnome-terminal -- bash -c "lf; exec bash"
           clear;
           show_menu;
            ;;
        #Menu Selection 8:Siftgrab Readme
        8) clear;
           read_me
           read -n1 -r -p "Press any key to continue..." key
           clear;
           show_menu;
            ;;
        x)exit;
        ;;
        \n)clear;
           exit;
        ;;
        *)clear;
        makered "Pick an option from the menu";
        show_menu;
        ;;
    esac
fi
done
}

#########DRIVE MOUNTING FUNCTIONS###########
#Report mount status
mount_status(){
     mount_stat=$(echo " /mnt/image_mount/" && [ "$(ls -A /mnt/image_mount/ 2>/dev/null)" ] && makered " Mounted" || makegreen " Not Mounted" )
     raw_stat=$(echo " /mnt/raw/" && [ "$(ls -A /mnt/raw/ 2>/dev/null)" ] && makered " Mounted"  || makegreen " Not Mounted")
     nbd_stat=$(echo " /dev/nbd1/" && [ "$(ls /dev/nbd1p* 2>/dev/null)" ] && makered " Active"  || makegreen " Inactive")
     vss_stat=$(echo " /mnt/vss/" && [ "$(ls /mnt/vss 2>/dev/null)" ] && makered " Active"  || makegreen " Inactive")
     vsc_stat=$(echo " /mnt/shadow/" && [ "$(ls /mnt/shadow 2>/dev/null)" ] && makered " Active"  || makegreen " Inactive")
     bde_stat=$(echo " /mnt/bde/" && [ "$(ls /mnt/bde 2>/dev/null)" ] && makered " Active"  || makegreen " Inactive")
}

#Set Source Disk Image File or Disk
function image_source(){
      read -e -p "Enter Image File or Device Path: " -i "" ipath
      image_type=$(echo "$ipath"|awk -F . '{print toupper ($NF)}')
      [ ! -f "${ipath}" ] && [ ! -b "${ipath}" ] && makered "File or Device does not exist.." && sleep 2 && clear && show_menu
      image_name=$(echo $ipath|sed 's/\(.*\)\..*/\1\./')
      [ $image_type == "ISO" ] && return 1
      multi=$image_name"002"
      printf "Image type "
      makegreen $image_type || makegreen "RAW"
      source_info=$(file "$ipath")
      echo "Source Information"
      makegreen $source_info
}

#Set mount directory (Default /mnt/image_mount)
function mount_point(){
      # Set Data Source or mount point"
      echo ""
      makegreen "Set Mount Point"
      echo "Set Path or Enter to Accept Default:"
      read -e -p "" -i "/mnt/image_mount" mount_dir
      mkdir -p $mount_dir
      [ "$mount_dir" ] || mkdir -p "$mount_dir"
      [ "$(ls -A $mount_dir)" ] && umount $mount_dir -f -A
      [ "$(ls -A $mount_dir)" ] && echo "$mount_dir busy, try different mount point or reboot" && sleep 2 && show_menu
      echo ""
}

#Set partition offset for disk images
function set_image_offset(){
     mmls $image_src 2>/dev/null && \
     makegreen "Set Partition Offset" && \
     read -e -p "Enter the starting block: " starting_block && \
     # Next line has been commented. Use default block size of 512
     # read -e -p "Set disk block size:  " -i "512" block_size && \
     partition_offset=$(echo $(($starting_block * 512))) && \
     makegreen "Offset: $starting_block * 512 = $partition_offset" && \
     offset="offset=$partition_offset"
}

#Mount images in expert witness format as raw image to /mnt/raw
function mount_e01(){
      [ 'which ewfmount' == "" ] && makered "ewf-tools not installed" && sleep 1 && exit
      image_src="/mnt/raw/ewf1"
      [ "$(ls -A /mnt/raw/)" ] && echo "Attempting to remount /mnt/raw/ " && umount /mnt/raw/ -f -A && makegreen "Sucessfully umounted previous E01"
      ewfmount "${ipath}" /mnt/raw   && makegreen "Success!" && ipath="/mnt/raw/ewf1" || exit
}

#Mount vmdk, vdi and qcow2 Image types as a network block device
function mount_nbd(){
     [ 'which qemu-nbd' == "" ] && makered "qemu-utils not installed" && sleep 1 && exit
     makered "Current Mount Status: "
     echo $nbd_stat
     echo $mount_stat
     [ -d "/dev/nbd1" ] && qemu-nbd -d /dev/nbd1 2>/dev/null && \
     rmmod nbd 2>/dev/null && echo "Warning: unloading and reloading nbd"
     modprobe nbd && echo "modprobe nbd"
     makegreen "qemu-nbd -r -c /dev/nbd1 "${ipath}"" && \
     qemu-nbd -r -c /dev/nbd1 "${ipath}" && ls /dev/nbd1  && makegreen "Success!" || exit
     image_src="/dev/nbd1"
}

#Mount raw split images using affuse
function mount_aff(){
     [ 'which affuse' == "" ] && makered "afflib-tools not installed" && sleep 1 && exit
     [ "$(ls -A /mnt/raw/)" ] && fusermount -uz /mnt/raw/
     [ "$(ls -A /mnt/raw/)" ] && echo "raw mount point in use, try manual unmount or reboot" && exit
     affuse "${ipath}" /mnt/raw && image_src=$(find /mnt/raw/ -type f)
}

#Decrypt bitlocker disks and mount partitions
function bit_locker_mount(){
     [ 'which bdemount' == "" ] && makered "bdemount is not installed" && sleep 1 && exit
     [ "${partition_offset}" != "" ] && offset="-o $partition_offset "
     [ "$(ls -A /mnt/raw/)" ] && \
     echo "" && makered "Bitlocker Encryption!!!" && makered "Enter decryption password or key"
     echo "-p <Password>"
     echo "-r <Authentication Key>"
     echo ""
     read -e -p "" bl_auth
     makegreen "Mounting with bdemount!!  "
     makegreen "bdemount $bl_auth $offset $ipath /mnt/bde"
     bdemount $bl_auth $offset $ipath /mnt/bde
     ls /mnt/bde/bde1 && makegreen "Unlocked!!" && offset="" && image_src="/mnt/bde/bde1"
     mount_image
}

#Issue Mount command based on image type and prefs
 function mount_image(){
      echo ""
      makegreen "Executing Mount Command....."
      echo "Defaults is ntfs, see mount man pages for a complete list"
      echo "Common filesystem types: ntfs, vfat, ext3, ext4, hfsplus, iso9660, udf"
      read -e -p "File System Type:  " -i "ntfs" fstype
      [ $fstype == "ntfs" ] && ntfs_support="show_sys_files,streams_interface=windows," && \
      umount_vss
      # Mount image to $mount_dir
      echo $image_src | grep -qiv "/dev/sd" && loop="loop,"
      mount_options="-t $fstype -o ro,"
      [ $image_type == "ISO" ] && mount_options=""
      [ "${block_device}" != "" ] && mount_options="-o ro,"
      mount=$(echo "mount $mount_options$loop$ntfs_support$offset "$image_src" $mount_dir"|sed 's/, / /')
      makegreen $mount
      $mount
      echo ""
      [ "$(ls -A $mount_dir)" ] && \
      echo "$ipath Mounted at: $mount_dir"
      echo ""
      ls $mount_dir
      echo ""
      [ "$(ls -A $mount_dir)" ] && \
      makegreen "Success!" || makered "Mount Failed! Try reboot or mount -o "norecovery""
      echo ""
      [ "$(ls -A $mount_dir)" ] && [ "$fstype" == "ntfs" ] && mount_vss
      show_menu
}

#Identify and choose whether to mount any vss volumes
function mount_vss(){
      [ 'which vshadowinfo' == "" ] && makered "libvshadow-utils not installed" && sleep 1 && show_menu
      vss_dir="/mnt/vss"
      vss_info=$(vshadowinfo $image_src 2>/dev/null |grep "Number of stores:")
      [ "${vss_info}" != "" ] && echo "VSCs found! "$vss_info && \
      echo "Mount Volume Shadow Copies?" && yes-no && vsc="yes"
      [ "${offset}" == "yes" ] && offset="-o $offset "
      [ "${vsc}" == "yes" ] && vshadowmount $image_src $offset$vss_dir && \
      ls $vss_dir | while read vsc;
      do
        mkdir -p /mnt/shadow/$vsc
        mount -t ntfs -o ro,loop,show_sys_files,streams_interface=windows /mnt/vss/$vsc /mnt/shadow/$vsc
      done  || show_menu
      ls /mnt/shadow/ && makegreen "Success! VSCs mounted on /mnt/shadow" || echo "No Volume Shadow Copies mounted"
}
#Identify and umount any previously mounted vss volumes
function umount_vss(){
      vss_dir="/mnt/vss"
      #umount any existing mounts
      fusermount -uz $vss_dir 2>/dev/null || return 1
      ls /mnt/shadow/ 2>/dev/null|while read vsc;
      do
        umount /mnt/shadow/$vsc 2>/dev/null
        rmdir /mnt/shadow/$vsc 2>/dev/null
        echo "/mnt/shadow/$vsc umounted"
      done
      rmdir /mnt/vss 2>/dev/null
}


#Umount drives before starting mount process
function umount_all(){
      echo "Umount commands sent to drives mounted in /tmp and NBD unloaded" && echo ""
      umount_vss
      [ "$(ls -A /mnt/bde 2>/dev/null)" ] && umount /mnt/bde -f -A || fusermount -uz /mnt/bde 2>/dev/null
      [ "$(ls -A /mnt/image_mount 2>/dev/null)" ] && umount /mnt/image_mount -f -A || fusermount -uz /mnt/image_mount 2>/dev/null
      [ "$(ls -A /mnt/raw/ 2>/dev/null)" ] && umount /mnt/raw -f -A || fusermount -uz /mnt/raw/ 2>/dev/null
      ls /dev/nbd1p1 2>/dev/null && qemu-nbd -d /dev/nbd1 2>/dev/null
      lsmod |grep -i ^nbd && rmmod nbd 2>/dev/null && echo "Warning: unloading Network Block Device"
      mount_status
}

####### DATA ACQUISITION AND PROCESSING PREFERENCES #######

# Set Data Source or mount point
function set_msource_path(){
      echo ""
      makered "SET DATA SOURCE"
      echo "Set Path or Enter to Accept Default:"
      read -e -p "" -i "/mnt/image_mount/" mount_dir
      [ ! -d "${mount_dir}" ] && makered "Path does not exist.." && sleep 1 && exit
....  mount_dir=$(echo $mount_dir |sed 's_.*_&\/_'|sed 's|//*|/|g')
      echo "Data Source =" $mount_dir
}

# Set Case Destination Folder (Default = /cases/)
function set_dsource_path(){
      makered "SET CASE DESTINATION FOLDER (Default = /cases/)"
      echo "Set Path or Enter to Accept:"
      read -e -p "" -i "/cases/" case_dir
      [ ! -d "${case_dir}" ] && makered "Path does not exist.." && sleep 2 && show_menu
      cd $case_dir
      [ ! -d "${case_dir}" ] && makered "Path does not exist.." && sleep 1 && show_menu
      case_dir="$case_dir/$comp_name"
}
function check_dsource_path(){
      [ -d "$case_dir/Triage" ] && echo "$case_dir already exists! overwrite?" && yes-no && rm -r $case_dir/Triage && quit="no"
      [ -d "$case_dir/Triage" ] && [ "$quit" != "no" ] && exit
      mkdir -p $case_dir/Triage
      echo "Case Folder =>  $case_dir"
}

#Find "Windows" directory paths
function set_windir(){
      cd $mount_dir
      windir=$(find $mount_dir -maxdepth 1 -type d |egrep -m1 -io windows$)
      winsysdir=$(find $mount_dir -maxdepth 2 -type d |egrep -m1 -io windows\/system32$)
      user_dir=$(find $mount_dir -maxdepth 1 -type d |grep -io users$)
      regdir=$(find $mount_dir/$winsysdir -maxdepth 2 -type d |egrep -m1 -io \/config$)
      [ "$windir" == "" ] || [ "$winsysdir" == "" ] && makered "No Windows Directory Path Found on Source..." && sleep 2 && show_menu
      echo "Windows System32 Directory => $mount_dir$winsysdir"
      echo  "Registry Directory" $mount_dir$winsysdir$regdir
}

#Get Computer Name using Regripper's "comp_name" plugin
function get_computer_name(){
   [ "$comp_name" == "" ] &&  \
   comp_name=$(find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f  |egrep -m1 -i /system$| while read d;
     do
       rip.pl -r "$d" -p compname 2>/dev/null |grep -i "computername   "|awk -F'= ' '{ print $2 }';done)
   [ "$comp_name" == "" ] && comp_name=$(date +'%Y-%m-%d-%H%M')
   echo "ComputerName:" $comp_name
   #cleanup and create a new new temp file to hold regripper output
   rm /tmp/$comp_name.* 2>/dev/null
   tempfile=$(mktemp /tmp/$comp_name.XXXXXXXX)
}

#Create Output Directory
function create_triage_dir(){
triage_dirs=("Account_Usage" "File_Access" "Malware" "Program_Execution"  "Regripper/NTUSER" "USB_Access" "WinEvent_Logs" "Browser_Activity"  "Persistence" "Registry_Settings" "Timeline/MFT" "Timeline/USNJRNL" "User_Searches" "Alert" "ActivitiesCache" "Outlook" "WindowsEventLogs")
    for dir_names in "${triage_dirs[@]}";
    do
      mkdir -p $case_dir/Triage/$dir_names
    done
    find "/$mount_dir/$user_dir/" -maxdepth 2 ! -type l|grep -i ntuser.dat$ |while read ntuser_path;
      do
        user_name=$( echo "$ntuser_path"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
        mkdir -p "$case_dir/Triage/Regripper/$user_name"
      done
}

##############ACQUISITION FUNCTIONS############################

#Check Size of Windows Logs and option to include in backup
function get_logsize(){
    cd $mount_dir
    find -maxdepth 1 -type d  -iname "inetpub"|while read d;
    do
      du -sh $d
    done
    find $winsysdir -maxdepth 2 -type d -iname "LogFiles"|while read d;
    do
      du -sh $d
    done
    makered "COPY WINDOWS LOGFILES?" && yes-no && get_logs="yes"
}

#Check USNJRNL Size and option to include in backup
function get_usnjrlnsize(){
    cd $mount_dir
    du -sh \$Extend/\$UsnJrnl:\$J
    makered "PROCESS \$USNJRNL File?"
}

#Copy Windows Journal file: USNJRNL:$J
function get_usnjrnl(){
    makegreen "Copying \$LogFile and  \$UsnJrnl:\$J"
    echo "#### USNJRNL ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    tar -Prvf $case_dir/$comp_name-acquisition.tar \$Extend/\$UsnJrnl:\$J | tee -a  $case_dir/Acquisition.log.txt
    echo ""
    tar -Prvf $case_dir/$comp_name-acquisition.tar \$LogFile | tee -a  $case_dir/Acquisition.log.txt
    echo ""
}

#Copy $MFT
function get_mft(){
    makegreen "Saving \$MFT "
    echo "#### MFT ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    echo $mount_dir
    tar -Prvf $case_dir/$comp_name-acquisition.tar \$MFT |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Windows Event Logs
function get_evtx(){
    makegreen "Saving Windows Event Logs"
    echo "#### Windows Event Logs ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $winsysdir/[W,w]inevt/[L,l]ogs -type f 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Windows Registry Files
function get_registry(){
    cd $mount_dir
    makegreen "Saving Windows Registry"
    echo "#### Windows Registry ####" >> $case_dir/Acquisition.log.txt
    find $winsysdir/[C,c]onfig -type f  2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy User profile registry hives (NTUSER.DAT)
function get_ntuser(){
    makegreen "Saving NTUSER.DAT"
    echo "#### NTUSER.DAT ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $user_dir -maxdepth 2 -mindepth 2 -type f -iname "ntuser.dat" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Userclass.dat files
function get_usrclass.dat(){
    makegreen "Saving usrclass.dat"
    echo "#### USRCLASS.DAT ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $user_dir/*/AppData/Local/Microsoft/Windows -maxdepth 2 -type f -iname "UsrClass.dat" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T -  |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy LNK and Jumplist file
function get_lnk_files(){
    makegreen "Saving LNK Files"
    echo "#### LNK AND JUMPLISTS ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $user_dir/*/AppData/Roaming/Microsoft/Windows/Recent -type f 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T -  |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Prefetch files
function get_prefetch(){
    makegreen "Saving Windows Prefetch"
    echo "#### PREFETCH ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $windir/[P,p]refetch  2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Amcache.hve and recentfilecache.bcf
function get_Amcache.hve(){
    makegreen "Saving Amcache.hve and Recentfilecache.bcf"
    echo "#### AMCACHE.HVE AND RECENTFILECACHE.BCF ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    # Get Amcache.hve
    find $windir/[a,A]*/[P,p]* -maxdepth 1 -type f -iname "Amcache.hve" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    # Get recentfilecache.bcf
    find $windir/[a,A]*/[P,p]* -maxdepth 1 -type f -iname "Recentfilecache.bcf" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy metadata files($I*.*) from Windows Recycle.bin
function get_Recycle.Bin(){
    makegreen "Copying RECYCLE BIN"
    echo "#### RECYCLEBIN $I ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find "\$Recycle.Bin" -type f -iname "*\$I*" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}
#Copy WebcacheV01.dat files
function get_webcachev(){
    makegreen "Saving WebcacheV01.dat"
    echo "#### MICROSOFT WEB BROWSER DB (WEBCACHEV01.DAT) ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $user_dir/*/AppData/Local/Microsoft/Windows/WebCache -maxdepth 2 -type f -iname "Webcach*.dat" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T -  |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Skype main.db files
function get_skype(){
    makegreen "Saving Skype"
    echo "#### SKYPE HISTORY ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $user_dir/*/AppData/Roaming/Skype/*/ -maxdepth 2 -type f -iname "main.db" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T -  |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy OBJECTS.DATA and *.mof files
function get_WMI_info(){
    # Get OBJECTS.DATA file
    makegreen "Saving OBJECTS.DATA and Mof files"
    echo "#### OBJECTS.DATA AND MOF ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $winsysdir/[W,w][B,b][E,e][M,m] -maxdepth 2 -type f  -iname "OBJECTS.DATA" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    # Get all Mof files
    find $winsysdir/[W,w][B,b][E,e][M,m]/*/ -maxdepth 2 -type f -iname "*.mof" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy SRUM.dat
function get_srumdb(){
    cd $mount_dir
    makegreen "Saving SRUM.DAT"
    echo "#### SRUM.DAT ####" >> $case_dir/Acquisition.log.txt
    find $winsysdir/[S,s][R,r][U,U]/ -maxdepth 1 -mindepth 1 -type f -iname "srumdb.dat" 2>/dev/null -print0|\
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy ActivitiesCache.db
function get_ActivitiesCache(){
    cd $mount_dir
    makegreen "Saving ActivitiesCache.db"
    echo "#### ActivitiesCache.db ####" >> $case_dir/Acquisition.log.txt
    find $user_dir/*/AppData/Local/ConnectedDevicesPlatform/ -maxdepth 1 -mindepth 1 -type f -iname "ActivitiesCache.db" 2>/dev/null -print0|\
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}


#Copy Setupapi logs
function get_setupapi(){
    cd $mount_dir
    makegreen "Saving Setupapi.dev.log"
    echo "#### SETUPAPI LOG FILES ####" >> $case_dir/Acquisition.log.txt
    find $windir/[I,i][N,n][F,f] -type f -iname "setupapi*log" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Scheduled Tasks
function get_scheduled_tasks(){
    makegreen "Saving Scheduled Tasks List"
    echo "#### SCHEDULED TASKS ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    #Tasks dir in Windows directory
    find $windir/[t,T]asks -type f 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    #Tasks dir in Windows/System32 directories
    find $winsysdir/[t,T]asks -type f 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
}

#Copy Windows log files
function get_logfiles(){
    makegreen "Saving Windows Log Files" && \
    echo "#### WINDOWS LOGFILES ####" >> $case_dir/Acquisition.log.txt
    find -maxdepth 1 -type d  -iname "inetpub" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    find $winsysdir -maxdepth 2 -type d -iname "LogFiles" -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Chrome metadata
function get_chrome(){
     makegreen "Copying CHROME Metadata"
    echo "#### CHROME ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $user_dir/*/AppData/Local/Google/Chrome/User\ Data/Default -maxdepth 2 -type f \
    \( -name "History" -o -name "Bookmarks" -o -name "Cookies" -o -name "Favicons" -o -name "Web\ Data" \
    -o -name "Login\ Data" -o -name "Top\ Sites" -o -name "Current\ *" -o -name "Last\ *" \)  2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Firefox Metadata
function get_firefox(){
    makegreen "Copying FIREFOX Metadata"
    echo "#### FIREFOX ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $user_dir/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/ -maxdepth 2 -type f \
    \( -name "*.sqlite" -o -name "logins.json" -o -name "sessionstore.jsonlz4" \)  2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}
########END DATA ACQUISITION FUNCTIONS######

######### PROCESSING FUNCTIONS##############

#Run select RegRipper plugins on Software Registry
function rip_software(){
    cd $case_dir
    makegreen "Running select RegRipper plugins on the Softare Registry Hive(s)"
    sleep 1
    find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -i "\/software$"| while read d;
    do
      rip.pl -r "$d" -p winver |tee -a $case_dir/Triage/Windows_Version_Info-$comp_name.txt;  # winnt_cv
      rip.pl -r "$d" -p lastloggedon |tee -a $case_dir/Triage/Account_Usage/Last-Logged-On-$comp_name.txt;
      rip.pl -r "$d" -p networklist 2>/dev/null |tee -a $case_dir/Triage/Account_Usage/Network-List-$comp_name.txt;
      rip.pl -r $d -p profilelist 2>/dev/null |tee -a $case_dir/Triage/Account_Usage/User-Profiles-$comp_name.txt;
      rip.pl -r $d -p pslogging 2>/dev/null |tee -a $case_dir/Triage/Account_Usage/Powershell-logging-$comp_name.txt;
      rip.pl -r "$d" -p portdev |tee -a $case_dir/Triage/USB_Access/USB_Device_List-$comp_name.txt;
      rip.pl -r "$d" -p runonceex |grep -va "^$"|tee -a $case_dir/Triage/Persistence/Run-Once-$comp_name.txt;
      rip.pl -r "$d" -p appcertdlls |grep -va "^$"|tee -a $case_dir/Triage/Persistence/Appcertsdlls-$comp_name.txt;
      rip.pl -r "$d" -p appinitdlls |grep -va "^$"|tee -a $case_dir/Triage/Persistence/appinitdlls-$comp_name.txt;
      rip.pl -r "$d" -p dcom |grep -va "^$"|tee -a $case_dir/Triage/Persistence/ports-$comp_name.txt;
      rip.pl -r "$d" -p psscript |grep -va "^$"|tee -a $case_dir/Triage/Persistence/Powershell-Script-$comp_name.txt;
      rip.pl -r "$d" -p listsoft |grep -va "^$"|tee -a $case_dir/Triage/Account_Usage/Software-Installed-$comp_name.txt;
      rip.pl -r "$d" -p msis |grep -va "^$"|tee -a $case_dir/Triage/Account_Usage/MSIexec-$comp_name.txt;
      rip.pl -r "$d" -p netsh |grep -va "^$"|tee -a $case_dir/Triage/Program_Execution/Netsh-$comp_name.txt;
      rip.pl -r "$d" -p srum |grep -va "^$"|tee -a $case_dir/Triage/Program_Execution/Srum-$comp_name.txt;
      rip.pl -r "$d" -p run |grep -va "^$"|tee -a $case_dir/Triage/Program_Execution/Srun-$comp_name.txt;
    done
    # rip all tlns to tempfile
    find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -i "\/software$"| while read d;
    do
      rip.pl -aT -r $d |sed "s/|||/|${comp_name}|${user_name}|/" >> $tempfile
    done
}

#Run select RegRipper plugins on the System Registry
function rip_system(){
    cd $case_dir
    makegreen "Running select RegRipper plugins on the System Registry Hive(s)"
    sleep 1
    find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -i -m1 "\/system$"| while read d;
    do
      rip.pl -r $d -p nic2 2>/dev/null |tee -a $case_dir/Triage/Account_Usage/Last-Networks-$comp_name.txt;
      rip.pl -r "$d" -p shares 2>/dev/null|tee -a $case_dir/Triage/Account_Usage/Share-Info-$comp_name.txt;
      rip.pl -r "$d" -p shimcache |tee -a $case_dir/Triage/Program_Execution/Shimcache-$comp_name.txt;
      rip.pl -r "$d" -p usbstor |tee -a $case_dir/Triage/USB_Access/USBStor-$comp_name.txt;
      rip.pl -r "$d" -p backuprestore |tee -a $case_dir/Triage/Persistence/Not-In-VSS-$comp_name.txt;
      rip.pl -r "$d" -p ntds |tee -a $case_dir/Triage/Persistence/ntds-$comp_name.txt;
      rip.pl -r "$d" -p devclass |tee -a $case_dir/Triage/USB_Access/USBdesc-$comp_name.txt;
      rip.pl -r "$d" -p lsa |tee -a $case_dir/Triage/Persistence/Lsa-$comp_name.txt;
      rip.pl -r "$d" -p rdpport |tee -a $case_dir/Triage/Account_Usage/RDP-Port-$comp_name.txt;
      rip.pl -r "$d" -p remoteaccess |tee -a $case_dir/Triage/Account_Usage/Remote-Access-Lockout-$comp_name.txt;
      rip.pl -r "$d" -p routes |tee -a $case_dir/Triage/Account_Usage/Routes-$comp_name.txt;
    done
    find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -i "\/system$"| while read d;
    do
      rip.pl -aT -r $d |sed "s/|||/|${comp_name}|${user_name}|/" >> $tempfile
    done
}

#Run select RegRipper plugins on the Security Registry
function rip_security(){
    cd $case_dir
    makegreen "Running select RegRipper plugins on the Security Registry Hive(s)"
    sleep 1
    find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -m1 -i "\/security$"| while read d;
    do
      rip.pl -r $d -p auditpol 2>/dev/null |tee -a $case_dir/Triage/Account_Usage/Audit-Policy-$comp_name.txt;
    done
    find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -i "\/security$" | while read d;
    do
      rip.pl -aT -r $d |sed "s/|||/|${comp_name}|${user_name}|/" >> $tempfile
    done
}

#Run all RegRipper plugins on NTUSER.DAT and Usrclass.dat
function regrip_ntuser_usrclass(){
    find "/$mount_dir/$user_dir/" -maxdepth 2 ! -type l|grep -i ntuser.dat$ |while read ntuser_path;
    do
      user_name=$( echo "$ntuser_path"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      usrclass_file=$(find /$mount_dir/$user_dir/"$user_name"/[aA]*[aA]/[lL]*[lL]/[mM][iI]*[tT]/[wW]*[sS] -maxdepth 3 -type f 2>/dev/null|grep -i -m1 "\/usrclass.dat$")
      echo $usrclass_file
      rip.pl -r "$ntuser_path" -a |tee -a "$case_dir/Triage/Regripper/$user_name/$comp_name-$user_name-NTUSER.txt"
      rip.pl -aT -r "$ntuser_path" |sed "s/|||/|${comp_name}|${user_name}|/" >> $tempfile
      rip.pl -r "$usrclass_file" -a |tee -a "$case_dir/Triage/Regripper/$user_name/$comp_name-$user_name-USRCLASS.txt"
      rip.pl -aT -r "$usrclass_file" |sed "s/|||/|${comp_name}|${user_name}|/" >> $tempfile
    done
}

#Run Select Regripper plugins on NTUSER.DAT
function regrip_user_plugins(){
    makegreen "Searching for NTUSER.DAT KEYS (Regripper)"
    sleep 1
    cd $mount_dir/$user_dir/
    find "/$mount_dir/$user_dir/" -maxdepth 2 ! -type l|grep -i ntuser.dat$ |while read ntuser_path;
    do
      user_name=$( echo "$ntuser_path"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      rip.pl -r "$ntuser_path" -p userassist |tee -a "$case_dir/Triage/Program_Execution/UserAssist-$user_name-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p recentdocs |tee -a "$case_dir/Triage/File_Access/$user_name-RecentDocuments-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$case_dir/Triage/User_Searches/ACMRU-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p runmru |grep -va "^$"|tee -a "$case_dir/Triage/Program_Execution/Run-MRU-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$case_dir/Triage/File_Access/opened-saved-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p comdlg32 |grep -va "^$"|tee -a "$case_dir/Triage/File_Access/opened-saved-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$case_dir/Triage/User_Searches/Wordwheel-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p wordwheelquery |grep -va "^$"|tee -a "$case_dir/Triage/User_Searches/Wordwheel-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$case_dir/Triage/User_Searches/Typedpaths-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p typedpaths |grep -va "^$"|tee -a "$case_dir/Triage/User_Searches/Typedpaths-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$case_dir/Triage/User_Searches/Typedurls-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p typedurls |grep -va "^$"|tee -a "$case_dir/Triage/User_Searches/Typedurls-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$case_dir/Triage/User_Searches/Typedurlstime-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p typedurlstime |grep -va "^$"|tee -a "$case_dir/Triage/User_Searches/Typedurlstime-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$case_dir/Triage/Program_Execution/Run_Open-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p run |grep -va "^$"|tee -a "$case_dir/Triage/Program_Execution/Run-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$case_dir/Triage/Registry_Settings/Compatibility_Apps-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p appcompatflags |grep -va "^$"|tee -a  "$case_dir/Triage/Registry_Settings/Compatibility_Apps-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$case_dir/Triage/Account_Usage/Logons-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p logonstats |grep -va "^$"|tee -a  "$case_dir/Triage/Account_Usage/Logons-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$case_dir/Triage/Program_Execution/Jumplist-Reg-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p jumplistdata |grep -va "^$"|tee -a  "$case_dir/Triage/Program_Execution/Jumplist-Reg-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$case_dir/Triage/Account_Usage/Mount-Points-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p mp2 |grep -va "^$"|tee -a  "$case_dir/Triage/Account_Usage/Mount-Points-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$case_dir/Triage/File_Access/Office-cache-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p oisc |grep -va "^$"|tee -a  "$case_dir/Triage/File_Access/Office-cache-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$case_dir/Triage/Persistence/Profiler-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p profiler |grep -va "^$"|tee -a "$case_dir/Triage/Persistence/Profiler-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$case_dir/Triage/Persistence/Load-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p load |grep -va "^$"|tee -a  "$case_dir/Triage/Persistence/Load-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$case_dir/Triage/Alert/NTUSER-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p rlo |grep -va "^$"|tee -a "$case_dir/Triage/Alert/NTUSER-$comp_name.txt"
    done
}

#Run RegRipper on SAM Registry hive
function regrip_sam(){
    cd $mount_dir
    makegreen "Searching for SAM (Regripper)"
    sleep 1
    counter="0" && find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -i "\/sam$"| while read d;
    do
      rip.pl -r "$d" -a |tee -a $case_dir/Triage/Account_Usage/SAM-$comp_name-$counter.txt && counter=$((counter +1));
    done
    find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -i "\/sam$" | while read d;
    do
      rip.pl -aT -r $d |sed "s/|||/|${comp_name}||/" >> $tempfile
    done
}

#Run RegRipper on AmCache.hve
function regrip_amcache.hve(){
    makegreen "Extracting Any RecentFileCache/AmCache (Regripper)"
    amcache_file=$(find $mount_dir/$windir/[a,A]*/[P,p]* -maxdepth 1 -type f |egrep -m1 -i \/amcache.hve$)
    rfc_bcf_file=$(find $mount_dir/$windir/[a,A]*/[P,p]* -maxdepth 1 -type f |egrep -m1 -i \/RecentFileCache.bcf$)

    [ "$amcache_file" ] && \
    rip.pl -aT -r "$amcache_file" |sed "s/|||/|${comp_name}|${user_name}|/"| tee -a $tempfile

    [ "$rfc_bcf_file" ] && \
    perl /usr/local/bin/rfc.pl "$rfc.bcf_file" |while read rfc;
    do
      echo "No Time Stamp, Recent File Cache, $comp_name, ,[Program Execution] RecentFileCache.bcf-"$rfc"" | tee -a $case_dir/Triage/Program_Execution/RecentFileCache.bcf-$comp_name.csv
    done
}

#Run Regripper on SysCache.hve
function regrip_syscache.hve_tln(){
  syscache_file=$(find "$mount_dir" -maxdepth 0 -type f 2>/dev/null|grep -i -m1 "System\ Volume\ Information\syscache.hve$" )
  [ "$syscache_file" ] && \
  rip.pl -aT -r "$syscache_file" >> $tempfile
}

function del_no_result(){
  cd $case_dir
  grep -RL ".:." /cases/ |while read d;
  do
    rm $d
  done
}


function lnkinfo(){
  cd $mount_dir
  find $mount_dir/$user_dir/*/ -type f|grep lnk$ | while read d;
  do
    echo $d && \
    /usr/bin/lnkinfo "$d"  |tee -a $case_dir/Triage/Program_Execution/lnkinfo-$comp_name.txt
  done
}


#Timeline recycle.bin metadata
function recbin2tln(){
    cd $mount_dir
    makegreen "Parsing \$Recycle.Bin"
    find $mount_dir/\$* -type f 2>/dev/null|grep "\$I"|sed 's|^\.||'|while read d;
    do
      ls $d
      sid=$(echo $d |sed 's|^\.||'|sed 's/^.*recycle.bin\///I'|awk -F'/' '{print $1}')
      name=$(strings -el -f $d)
      hexsize=$(cat "$d"|xxd -s8 -l8 -ps| sed -e 's/[0]*$//g')
      size=$(echo $((0x$hexsize)))
      hexdate0=$(cat "$d"|xxd -ps -s16 -l8 |grep -o .. |tac| tr -d '\n')
      #hexdate0=$(cat "$d"|xxd -s16 -l8 -ps|awk '{gsub(/.{2}/,"& ")}1'|awk '{for(i=NF; i>0;i--)printf "%s",$i}' && echo "")
      epoch=$(echo $((0x$hexdate0/10000000-11644473600)))
      #epoch=$(echo $(($hexdate1-11644473600)))
      date=$(date -d @$epoch +"%Y-%m-%d %H:%M:%S")
      echo "$epoch|Recycle|"$comp_name"||[Deleted] "$name " FILE SIZE: "$size| tee -a  >> $tempfile
      echo "$date,Recycle,"$comp_name",,[Deleted] "$name " FILE SIZE: "$size| tee -a $case_dir/Triage/File_Access/Recycled.csv
      echo "hexdateraw" $hexdate0
    done
}

#Timeline Chrome metadata
function chrome2tln(){
    makegreen "Extracting Any CHROME HISTORY and DOWNLOADS (sqlite3)"
    cd $mount_dir
    find $user_dir/*/AppData/Local/Google/Chrome/User\ Data/Default -maxdepth 0 -type d |while read d;
    do
      echo $d
      user_name=$(echo "$d"|sed 's/\/AppData.*//'|sed 's/^.*\///')
      makegreen "Searching for CHROME HISTORY and DOWNLOADS (sqlite3)"

      #Extract Chrome Browsing history
      [ "$d/History" != "" ] && \
      sqlite3 "$d/History" "select datetime(last_visit_time/1000000-11644473600, 'unixepoch'),url, title, visit_count from urls ORDER BY last_visit_time" | \
      awk -F'|' '{print $1",chrome,,,[URL]:"$2",TITLE: "$3", VISIT COUNT:"$4}'| \
      sed "s/,,,/,${comp_name},${user_name},/" | tee -a "$case_dir/Triage/Browser_Activity/$user_name-Chrome-History-$comp_name.csv"

      # Extract Chrome Downloads
      [ "$d" != "" ] && \
      sqlite3 "$d/History" "select datetime(start_time/1000000-11644473600, 'unixepoch'), url, target_path, total_bytes FROM downloads INNER JOIN downloads_url_chains ON downloads_url_chains.id = downloads.id ORDER BY start_time" | \
      awk -F'|' '{print $1",chrome,,,[DOWNLOAD]-"$2",TARGET:-"$3", BYTES TRANSFERRED:-"$4}' | \
      sed "s/,,,/,${comp_name},${user_name},/" | tee -a "$case_dir/Triage/Browser_Activity/$user_name-Chrome-Download-$comp_name.csv"

      #Extract Chrome cookies
      [ "$d" != "" ] && \
      sqlite3 "$d/Cookies" "select datetime(cookies.creation_utc/1000000-11644473600, 'unixepoch'), cookies.host_key,cookies.path, cookies.name, datetime(cookies.last_access_utc/1000000-11644473600,'unixepoch','utc'), cookies.value FROM cookies"| \
      awk -F'|' '{print $1",chrome,,,[Cookie Created]:"$2" LASTACCESS: "$5" VALUE: "$4}'| \
      sed "s/,,,/,${comp_name},${user_name},/" | tee -a "$case_dir/Triage/Browser_Activity/$user_name-Chrome-Cookies-$comp_name.csv"

      #Extract Chrome Login Data
      [ "$d" != "" ] && \
      sqlite3 "$d/Login Data" "select datetime(date_created/1000000-11644473600, 'unixepoch'),  origin_url,username_value,signon_realm FROM logins"| \
      awk -F'|' '{print $1",chrome,,,[Login Data]:SITE_ORIGIN:"$2" USER_NAME: "$3" SIGNON_REALM "$4}' |\
      sed "s/,,,/,${comp_name},${user_name},/" | tee -a "$case_dir/Triage/Browser_Activity/$user_name-Chrome-LoginData-$comp_name.csv"
      #Extract Chrome Web Data
      [ "$d" != "" ] && \
      sqlite3 "$d/Web Data" "select datetime(date_last_used, 'unixepoch'), name,value, count, datetime(date_created, 'unixepoch') from autofill"|\
      awk -F'|' '{print $1",chrome,,,[WebData] CREATED:"$5" NAME:"$2" VALUE:"$3" COUNT:"$4}'| \
      sed "s/,,,/,${comp_name},${user_name},/" |tee -a "$case_dir/Triage/Browser_Activity/$user_name-Chrome-WebData-$comp_name.csv"

      #Extract Chrome Bookmarks
      [ "$d" != "" ] && \
      cat "$d/Bookmarks" |jq -r '.roots[]|recurse(.children[]?)|select(.type != "folder")|{date_added,name,url}|join("|")'|\
      awk -F'|' '{print int($1/1000000-11644473600)"|"$2"|"$3}'| \
      awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1",Chrome,,,[Bookmark Created] NAME:"$2" URL:"$3}' |\
      sed "s/,,,/,${comp_name},${user_name},/" | tee -a "$case_dir/Triage/Browser_Activity/$user_name-Chrome-Bookmarks-$comp_name.csv"
    done

    # Copy Files to Timeline Temp File
    find $case_dir/Triage/Browser_Activity/ -type d |grep "Chrome" | while read d;
    do
      echo "$d"| while read f;
        do
        timestamp=$(echo "$f"| awk -F',' '{print $1}'| grep -E '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) (2[0-3]|[01][0-9]):[0-5][0-9]:[0-5][0-9]')
          [ "$timestamp" != "" ] && tlntime=$(date -d "$timestamp"  +"%s" 2>/dev/null)
          tlninfo=$(echo "$f"| awk -F',' '{print "|"$2"|"$3"|"$4"|"$5}')
          [ "$timestamp" != "" ] && echo $tlntime$tlninfo | >> $tempfile
        done
      done
}

#Timeline Firefox metadata
function firefox2tln(){
    makegreen "Extracting Any Firefox HISTORY, DOWNLOADS and COOKIES (sqlite3)"
    cd $mount_dir
    find $user_dir/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/ -maxdepth 0 -type d 2>/dev/null|while read d;
    do
      user_name=$(echo "$d"|sed 's/\/AppData.*//'|sed 's/^.*\///')
      #Extract FireFox Browsing history (places.sqlite)
      [ -e "$d/places.sqlite" ] && \
      sqlite3 file:"$d/places.sqlite" "select (moz_historyvisits.visit_date/1000000), moz_places.url, moz_places.title, moz_places.visit_count FROM moz_places,moz_historyvisits where moz_historyvisits.place_id=moz_places.id order by moz_historyvisits.visit_date;" |\
      awk -F'|' '{print $1"|FireFox|||[URL]:"$2"  TITLE:"$3" VISIT-COUNT:" $4}'| sed "s/|||/|${comp_name}|${user_name}|/" |\
      tee -a "$case_dir/Triage/Browser_Activity/$user_name-FireFox-History-$comp_name.csv"

      # Extract FireFox Downloads
      [ -e "downloads.sqlite" ] && \
      sqlite3 file:"$d/places.sqlite" "select (startTime/1000000), source,target,currBytes,maxBytes FROM moz_downloads" |awk -F'|' '{print $1"|FireFox|||[Download]:"$2"=>"$3" BYTES DOWNLOADED=>"$4" TOTAL BYTES=>"$5}' | sed "s/|||/|${comp_name}|${user_name}|/" | \
      tee -a "$case_dir/Triage/Browser_Activity/$user_name-FireFox-Downloads-$comp_name.csv"

      #Extract FireFox cookies
      [ -e "cookies.sqlite" ] && \
      sqlite3 file:"$d/cookies.sqlite" "select (creationTime/1000000), host,name,datetime((lastAccessed/1000000),'unixepoch','utc'),datetime((expiry/1000000),'unixepoch','utc') FROM moz_cookies" |\
      awk -F'|' '{print $1"|FireFox||| [Cookie Created]: "$2" NAME:"$3" ,LAST ACCESS:"$4", EXPIRY: "$5}'| \
      sed "s/|||/|${comp_name}|${user_name}|/" | \
      tee -a "$case_dir/Triage/Browser_Activity/$user_name-FireFox-Cookies-$comp_name.csv"
    done
    # Copy Files to Timeline Temp File
    find $case_dir/Triage/Browser_Activity/ -type d |grep "FireFox" 2>/dev/null| while read d;
    do
      echo "$d"| while read f;
        do
        timestamp=$(echo "$f"| awk -F',' '{print $1}'| grep -E '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) (2[0-3]|[01][0-9]):[0-5][0-9]:[0-5][0-9]')
          [ "$timestamp" != "" ] && tlntime=$(date -d "$timestamp"  +"%s" 2>/dev/null)
          tlninfo=$(echo "$f"| awk -F',' '{print "|"$2"|"$3"|"$4"|"$5}')
          [ "$timestamp" != "" ] && echo $tlntime$tlninfo | >> $tempfile
        done
      done
}


function extract_webcacheV(){
    cd $mount_dir/$user_dir/
    makegreen "Extracting any IE WebcacheV0x.dat files (esedbexport)"
    find "$mount_dir/$user_dir/" -maxdepth 2 ! -type l|grep -i ntuser.dat$ |while read ntuser_path;
    do
      user_name=$( echo "$ntuser_path"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      find /$mount_dir/$user_dir/$user_name/AppData/Local/Microsoft/Windows/WebCache -maxdepth 2 -type f -iname "WebcacheV*.dat" 2>/dev/null |while read d;
      do
        echo "Found $d"
        /usr/bin/esedbexport -t $case_dir/Triage/Browser_Activity/IEWebcache-$user_name-$comp_name "$d";
      done
    done
}

#Timeline Skype metadata
function skype2tln(){
    makegreen "Extracting Any Skype History Logs (sqlite3)"
    cd $mount_dir/$user_dir/
    find "$mount_dir/$user_dir/" -maxdepth 2 ! -type l|grep -i ntuser.dat$ |while read ntuser_path;
    do
      user_name=$( echo "$ntuser_path"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      main_db=$(find $mount_dir/$user_dir/"$user_name"/ |grep -i appdata.roaming.skype|grep -i main.db)
      find "$mount_dir/$user_dir/$user_name"|grep -i appdata.roaming.skype|grep -i main.db$ |while read maindb;
      do
        #contacts
        sqlite3 file:"$maindb" 'select profile_timestamp,skypename, fullname,displayname from Contacts'|
        awk -F'|' '{print $1"|Skype|||NEW CONTACT: "$2", "$3", "$4}'|
        sed 's|^\||0\||'| sed "s/|||/|${comp_name}|${user_name}|/" |tee -a $tempfile

        messages
        sqlite3 file:"$maindb" 'select timestamp,body_xml,author,dialog_partner from Messages'| \
        awk -F'|' '{print $1"|Skype|||MESSAGE: "$2", FROM:"$3","$4}'|
        sed 's|^\||0\||' | sed "s/|||/|${comp_name}|${user_name}|/"| tee -a $tempfile

        #Voicemail
        sqlite3 file:"$maindb" 'select timestamp,partner_dispname,path from Voicemails'| \
        awk -F'|' '{print $1"|Skype|||VOICEMAIL FROM: "$2" FILE: "$3}'|
        sed 's|^\||0\||' | sed "s/|||/|${comp_name}|${user_name}|/" |tee -a $tempfile

        #Conversations
        sqlite3 file:"$maindb" 'select creation_timestamp,displayname from Conversations' 2>/dev/null| \
        awk -F'|' '{print $1"|Skype|||CONVERSATION STARTED: "$2}'|
        sed 's|^\||0\||'| sed "s/|||/|${comp_name}|${user_name}|/" |tee -a $tempfile

        sqlite3 file:"$maindb" 'select last_activity_timestamp, displayname from Conversations' 2>/dev/null| \
        awk -F'|' '{print $1"|Skype|||CONVERSTATION END: " $2}'|
        sed 's|^\||0\||'| sed "s/|||/|${comp_name}|${user_name}|/" |tee -a $tempfile

        #File Transfer
        sqlite3 file:"$maindb" 'select starttime, filepath,bytestransferred,partner_dispname from Transfers' 2>/dev/null|\
        awk -F'|' '{print $1"|Skype|||FILE TRANSFER:" $2}'|
        sed 's|^\||0\||' | sed "s/|||/|${comp_name}|${user_name}|/" | tee -a $tempfile
      done
    done

}

#Timeline Alternate Data Streams
function ADS_extract(){
    cd $mount_dir

    #  scan mounted NTFS disk Alternate Data Streams and Timestamps
    [ "$(getfattr -n ntfs.streams.list $mount_dir 2>/dev/null)" ]  && makegreen "Extracting Alternate Data Streams" &&\
    getfattr -Rn ntfs.streams.list . 2>/dev/null |\
    grep -ab1 -h ntfs.streams.list=|grep -a : |sed 's/.*ntfs.streams.list\="/:/g'|\
    sed 's/.*# file: //'|sed 's/"$//g'|paste -d "" - -|grep -v :$ | while read ADS_file;
    do
      base_file=$(echo "$ADS_file"|sed 's/:.*//')
      crtime=$(getfattr -h -e hex -n system.ntfs_times_be "$base_file" 2>/dev/null|grep "="|awk -F'=' '{print $2}'|grep -o '0x................')
      epoch_time=$(echo $(($crtime/10000000-11644473600)))
      [ $epoch_time ] || epoch_time="0000000000"
      MAC=$(stat --format=%y%x%z "$base_file" 2>/dev/null)
      [ "$ADS_file" ] && echo "$epoch_time|ADS|$comp_name||[ADS Created]: $ADS_file [MAC]: $MAC"|grep -va "ntfs.streams.list\="|tee -a $tempfile
      [ "$ADS_file" ] && echo "$epoch_time|ADS|$comp_name||[ADS Created]: $ADS_file [MAC]: $MAC" |grep -va "ntfs.streams.list\="|grep Zone.Identifier| tee -a $case_dir/Triage/Browser_Activity/Zone.Identifier-$comp_name.csv
    done
}

#Timeline Prefetch and extract metadata
function prefetch_extract(){
    cd $mount_dir
    makegreen "Searching for PREFETCH (prefetchruncounts.py)"
    sleep 1
    find "/$mount_dir/$windir/" -maxdepth 2 -type d -iname "Prefetch" |sed 's/$/\//'| while read d;
    do
      python /usr/local/bin/prefetchruncounts.py "$d" -o $case_dir/Triage/Program_Execution/Prefetch-$comp_name
    done

    find $case_dir/Triage/Program_Execution |grep run_count |while read d;
    do
    cat $d | while read line;
      do
        timestamp=$(echo $line| awk -F',' '{print $1}'| grep -Eo '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) (2[0-3]|[01][0-9]):[0-5][0-9]:[0-5][0-9]')
        [ "$timestamp" != "" ] && tlntime=$(date -d "$timestamp"  +"%s" 2>/dev/null)
        tlninfo=$(echo $line| awk -F',' '{print "[Program Execution] File:"$2" Run Count:"$4" Vol_ID:"$8" "$11}')
        [ "$timestamp" != "" ] && echo $tlntime"|prefetch|"$comp_name"||"$tlninfo | tee -a $tempfile
      done
    done
}

#Timeline Windows Services
function winservices(){
    cd $mount_dir
    makegreen "Searching for windows Services (winservices.py)"
    sleep 1
    counter="0" && find $mount_dir/$winsysdir/$regdir -type f 2>/dev/null | grep -i \/system$| while read d;
    do
      python /usr/local/bin/winservices.py "$d" |tee -a $case_dir/Triage/Persistence/WindowsServices-$comp_name-$counter.txt && counter=$((counter +1));
    done

    find $case_dir/Triage/Persistence/ -type f |grep "WindowsServices-" | while read d;
    do
      cat "$d" |while read f;
        do
          timestamp=$(echo "$f" awk -F',' '{print $1}'| grep -Eo '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) (2[0-3]|[01][0-9]):[0-5][0-9]:[0-5][0-9]')
          tlntime=$(date -d "$timestamp"  +"%s" 2>/dev/null)
          tlninfo=$(echo "$f"| awk -F',' '{print "||[Service Last Write]: "$2","$3","$5","$7}')
          echo $tlntime"|Reg|"$comp_name$tlninfo |tee -a $tempfile
        done
    done
}

#Consolidating TLN Output and consolidating timelines
function consolidate_timeline(){
    makegreen "Consolidating TLN Files"
    echo ""
    cat $tempfile | sort -rn |uniq | tee -a | tee -a $case_dir/Triage/Timeline/Triage-Timeline-$comp_name.TLN;
    cat $tempfile |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'|sort -rn | uniq| grep -va ",,,," |tee -a $case_dir/Triage/Timeline/Triage-Timeline-$comp_name.csv.txt
    cat $case_dir/Triage/Timeline/Triage-Timeline-$comp_name.csv.txt| grep Skype -a | tee -a $case_dir/Triage/Browser_Activity/Skype-$comp_name.csv
    cat $case_dir/Triage/Timeline/Triage-Timeline-$comp_name.csv.txt|grep -ia ",alert," |tee -a $case_dir/Triage/Alert/RegRipperAlerts-$comp_name.csv
    makegreen "Complete!"
}

#copy setupapi logs
function cp_setupapi(){
    cd $mount_dir
    makegreen "Copying setupapi.dev.log"

    find $case_dir -type f 2>/dev/null | grep -i setupapi.dev.log | grep -i log$ |while read d;
    do
      cp "$d" $case_dir/Triage/USB_Access/setupapi.dev.log-$comp_name.txt 2>/dev/null;
    done
}

#Run Jobparse.py and Extract Windows Event Log: TaskScheduler%4operational.evtx
function extract_Jobs(){
    cd $mount_dir
    makegreen "Searching for SCHEDULED TASKS (jobparser.py)"
    sleep 1
    find $windir -maxdepth 2 -type d 2>/dev/null  | grep -i '\/tasks$'|sed 's|^\./||'|while read d;
    do
      echo "######## $d ########" |tee -a $case_dir/Triage/Persistence/Jobs-$comp_name.txt
      python2 /usr/local/bin/jobparser.py -d "$d" |tee -a $case_dir/Triage/Persistence/Jobs-$comp_name.txt;
    done
}

#Parse OBJECTS.DATA file
extract_objects_data(){
    cd $mount_dir
    makegreen "Searching for Object.data file (PyWMIPersistenceFinder.py, CCM-RecentApps.py)"
    sleep 1
    find $winsysdir -maxdepth 3 -type f 2>/dev/null  | grep -i '\/objects.data$'|sed 's|^\./||'|while read d;
    do
      python2 /usr/local/bin/CCM_RUA_Finder.py -i "$d" -o $case_dir/Triage/Program_Execution/CCM-RecentApps-$comp_name.csv
      python2 /usr/local/bin/PyWMIPersistenceFinder.py -i "$d" -o $case_dir/Triage/Persistence/WMI-Persistence-$comp_name.csv
    done
}

#Parse Windows History File
extract_winactivities(){
    cd $mount_dir
    makegreen "Searching for ActivitiesCache.db"
    cd $mount_dir/$user_dir/
    find "$mount_dir/$user_dir/" -maxdepth 2 ! -type l|grep -i ntuser.dat$ |while read ntuser_path;
    do
      user_name=$( echo "$ntuser_path"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      find "$mount_dir/$user_dir/$user_name/AppData/Local/ConnectedDevicesPlatform" -maxdepth 5 -type f 2>/dev/null | \
      grep -i "ActivitiesCache.db$"| sed 's|^\./||'|while read d;
      do
        echo "$d"
        sqlite3 "$d" ".read /usr/local/src/kacos2000/WindowsTimeline/WindowsTimeline.sql" | tee -a $case_dir/Triage/ActivitiesCache/Activity-$user_name-$comp_name.csv
      done
    done
}

#Parse IE History File Index.dat
parse_index.dat(){
    cd $mount_dir
    makegreen "Searching for any index.dat files"
    cd $mount_dir/$user_dir/
    find "$mount_dir/$user_dir/" -maxdepth 2 ! -type l|grep -i ntuser.dat$ |while read ntuser_path;
    do
      user_name=$( echo "$ntuser_path"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      find "$mount_dir/$user_dir/$user_name/AppData" -size +5k -maxdepth 9 -type f 2>/dev/null | \
      grep -i \/index.dat$ | sed 's|^\./||'|while read d;
      do
        parseie.pl -t -s $comp_name -u $user_name -f "$d"| grep -Ev ietld\|iecompat >> $tempfile
        parseie.pl -t -s $comp_name -u $user_name -f "$d" | grep -Ev ietld\|iecompat |\
        awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'| \
        tee -a $case_dir/Triage/Browser_Activity/Index.dat-$user_name-$comp_name.csv
      done
    done
}

# Extract WindowsEvent Logs
function extract_WinEVTX(){
    cd $mount_dir
    makegreen "Searching for windows Event Logs"
    sleep 1
    find $mount_dir/ -type f 2>/dev/null | grep -i \/security.evtx$| while read d;
    do
      python /usr/local/bin/parse_evtx_logins.py "$d" |tee -a $case_dir/Triage/WindowsEventLogs/Windows-Logins-$comp_name.txt;
      python /usr/local/bin/parse_evtx_processes.py "$d" |tee -a $case_dir/Triage/WindowsEventLogs/Windows-processes-$comp_name.txt;
      python /usr/local/bin/parse_evtx_accounts.py "$d" |tee -a $case_dir/Triage/WindowsEventLogs/Windows-accounts-$comp_name.txt;
    done
    #Microsoft-Windows-TaskScheduler4Operational.evtx
    find $mount_dir/ -type f 2>/dev/null | grep -i \/Microsoft-Windows-TaskScheduler\%4Operational.evtx$| while read d;
    do
      python /usr/local/bin/parse_evtx_tasks.py "$d" |tee -a $case_dir/Triage/WindowsEventLogs/Task-Scheduler-$comp_name.txt;
    done
}

#Extract MFT to body file and then to TLN and csv files
function analyze_mft(){
    cd $mount_dir
    makegreen "Analyzing \$MFT Standby..."
    [ -f "\$MFT" ] && \
    python2 /usr/local/bin/analyzeMFT.py -p -f \$MFT --bodyfull --bodyfile=$case_dir/Triage/Timeline/MFT/MFT-$comp_name.body
    [ -f $case_dir/Triage/Timeline/MFT/MFT-$comp_name.body ] && bodyfile.pl -f $case_dir/Triage/Timeline/MFT/MFT-$comp_name.body -s $comp_name | \
    sort -rn |tee $case_dir/Triage/Timeline/MFT/MFT-$comp_name.TLN.txt && \
    cat $case_dir/Triage/Timeline/MFT/MFT-$comp_name.TLN.txt | awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'| \
    tee -a $case_dir/Triage/Timeline/MFT/MFT-$comp_name.csv
    mft_dump \$MFT -o csv -f $case_dir/Triage/Timeline/MFT/MFT_Dump-$comp_name.csv
}

#Extract $USNJRNL:$J to TLN
function parse_usn(){
    cd $mount_dir
    makegreen "Extracting \$USNJRNL:$J Standby..."
    [ -f "\$Extend/\$UsnJrnl:\$J" ] && \
    python2 /usr/local/bin/usn.py -t -s $comp_name -f "\$Extend/\$UsnJrnl:\$J"  -o $case_dir/Triage/Timeline/USNJRNL/USNJRNL-$comp_name.TLN.txt
    cat $case_dir/Triage/Timeline/USNJRNL/USNJRNL-$comp_name.TLN.txt | awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'| \
    tee -a $case_dir/Triage/Timeline/USNJRNL/USNJRNL-$comp_name.csv
}

# Find and extract Outlook files
function extract_Outlook_pst_ost(){
    cd $mount_dir/$user_dir/
    counter=0
    find "$mount_dir/$user_dir/" -maxdepth 2 ! -type l 2>/dev/null|grep -i ntuser.dat$ |while read ntuser_path;
    do
      user_name=$( echo "$ntuser_path"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      makegreen "Searching for OUTLOOK EMAIL Files to extract (pffexport)"
      find $mount_dir -type f 2>/dev/null |grep -Ei "\.pst$"\|"\.ost$"|while read d;
      do
        pffexport "$d" -t $case_dir/Triage/Outlook/$user_name$counter && counter=$((counter +1))
      done
    done
}

# Collect Volatilile data files and copies them to the cases folder
function get_volatile(){
    cd $mount_dir
    find -maxdepth 1 -iname "*file.sys" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-volatile-files.tar --null -T -
    find -maxdepth 1 -iname "*hiberfil.sys" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-volatile-files.tar --null -T -
    gzip -f $case_dir/$comp_name-volatile-files.tar
    makegreen "Complete!!"
}

clear
[ $(whoami) != "root" ] && makered "Siftgrab Requires Root!" && exit
show_menu
exit 0