#!/bin/bash

#******************************************************************************
#   John Forecast (C) 2023                     john@forecast.name
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#******************************************************************************

# Shell script to download, build and install Linux DECnet.
#
# This file should be placed in, an initially empty, directory which will
# be used to hold the DECnet source files. If it finds the DECnet source
# tree is present, it will ask if it should download a new version.

CAT=/bin/cat
CHMOD=/bin/chmod
CP=/bin/cp
CUT=/usr/bin/cut
DATE=/bin/date
EXPR=/usr/bin/expr
GIT=/usr/bin/git
GREP=/bin/grep
MAKE=/usr/bin/make
MKDIR=/usr/bin/mkdir
MV=/bin/mv
PRINTF=/usr/bin/printf
PWD=/bin/pwd
RM=/bin/rm
TRUE=/bin/true
SYSTEMCTL=/usr/bin/systemctl

# Debian tools
APTGET=/usr/bin/apt-get
DPKG=/usr/bin/dpkg

# Redhat/Fedora tools
RPM=/usr/bin/rpm

Here=`$PWD`
Log=$Here/Log

DECnetDownload=1
DECnetConfig=1
Pause=1

MACchange=0
Start=0

Name=
Addr=
Area=0
Node=0
Interface=

if [[ ${EUID} -ne 0 ]]; then
    echo "You must be a root user to run this script" 2>&1
    exit 1
fi

PKGLIST="gcc git libssl-dev make linux-libc-dev"

#
# Useful functions
#
check_addr() {
    if [ ! -z "$1" ]; then
        if [ `$EXPR $1 : '[0-9]*\.[0-9]*'` -ne "`$EXPR length $1`" ]; then
            echo "Node address must be in the format area.node"
            return 0
        fi

        AreaNo=`echo $1 | $CUT -d. -f1`
        NodeNo=`echo $1 | $CUT -d. -f2`

        if [ "$AreaNo" -le 0 -o "$AreaNo" -ge 64 ]; then
            echo "Area must be between 1 and 63 inclusive"
            return 0
        fi

        if [ "$NodeNo" -le 0 -o "$NodeNo" -ge 1024 ]; then
            echo "Node must be between 1 and 1023 inclusive"
            return 0
        fi
        return 1
    fi
    return 0
}

check_name() {
    if [ "`$EXPR length "$1"`" -le 6 ]; then
        if [ `$EXPR "$1" : '[0-9a-zA-Z]*'` -ne "`$EXPR length "$1"`" ]; then
            echo "DECnet node names may be up to 6 alphanumeric characters"
            return 0
        fi
	if [ `$EXPR "$1" : '[0-9]*'` -eq "`$EXPR length "$1"`" ]; then
	    echo "DECnet node names must include at least 1 alpha character"
	    return 0
	fi
        return 1
    fi
    return 0
}

check_interface() {
    $GREP -q "$1:" /proc/net/dev
    if [ $? -ne 0 ]; then
        echo "Can't find device $1 on your system. Choose one of the following:"
        awk '/.*:/ { print substr($1,0,index($1, ":")) }' < /proc/net/dev
        return 0
    fi
    return 1
}

DOCMD() {
    echo "$1" >> $Log
$1 >> $Log 2>&1
return $?
}

#

check_headers() {
    if [ "${HAVE_HEADERS}" = "1" ]; then
	if [ -d /lib/modules/$(uname -r)/source/include ]; then
	    return
	fi
    fi
    PKGLIST="${PKGLIST} linux-headers-$(uname -r)"
}

determine_os() {
    case $1 in
	raspbian|debian)
	    if [ -x ${APTGET} -a -x ${DPKG} ]; then
		for pkg in ${PKGLIST}
		do
		    ${DPKG} -s $pkg >/dev/null 2>&1
		    if [ $? -ne 0 ]; then
			echo -n "Installing $pkg ..."
			${APTGET} install -y $pkg >/dev/null 2>&1
			if [ $? -ne 0 ]; then
			    echo "Failed to install package '" $pkg "'"
			    exit 1
			fi
			echo
		    fi
		done
		return 1
	    fi
	    ;;

	rhel|sles|fedora|centos)
	    if [ -x ${RPM} ]; then
	        for pkg in ${PKGLIST}
		do
		    ${RPM} -q $pkg >/dev/null 2>&1
		    if [ $? ne 0 ]; then
			echo -n "Installing $pkg ..."
			${RPM} -i $pkg >/dev/null 2>&1
			if [ $? ne 0 ]; then
			    echo "Failed to install package '" $pkg "'"
			    exit 1
			fi
			echo
		    fi
		done
		return 1
	    fi
	    ;;
    esac
    return 0
}

unknown_os() {
    echo "Unable to determine which package manager to use"
    echo "The following packages must be installed for this script to work:"
    echo
    echo "    ${PKGLIST}"
}

# Make sure that all required packages are installed

if [ -e /etc/os-release ]; then
    check_headers

    source /etc/os-release

    while $TRUE ; do
	determine_os ${ID}
	if [ $? -eq 1 ]; then
	    break
	fi

	if [ ! -z ${ID_LIKE} ]; then
	    determine_os ${ID_LIKE}
	    if [ $? -1 eq 1 ]; then
		break
	    fi
	fi
	unknown_os
    done
else
unknown_os
fi

if [ -d ./LinuxDECnet ]; then
    while ${TRUE} ; do
	echo "There appears to be an existing Linux DECnet source tree present"
	echo "Do you want to:"
	echo "  1 - Delete existing tree, download a new one and build"
	echo "  2 - Clean and rebuild using the existing tree"
	echo "  3 - Rebuild using the existing tree"
	echo "  4 - Install everything already built in the existing tree"
	echo
	read -p "Enter code (1 - 4): " DECnetDownload Junk

	if [ "$Junk" = "" ]; then
	    case $DECnetDownload in
		1|2|3|4)
		    break
		    ;;
	    esac
	fi
	echo "Invalid Response"
	echo
    done
fi

if [ -e /etc/decnet.conf ]; then
    while ${TRUE} ; do
	echo
	echo "There appears to be an existing DECnet configuration present"
	echo "Do you want to:"
	echo "  1 - Delete the existing configuration files and create new ones"
	echo "  2 - Use the existing configuration files"
	echo
	read -p "Enter code (1 - 2): " DECnetConfig Junk

	if [ "$Junk" = "" ]; then
	    case $DECnetConfig in
		1|2)
		    break
		    ;;
	    esac
	fi
	echo "Invalid Response"
	echo
    done
fi

echo
while ${TRUE} ; do
    echo "When the build completes, do you want to:"
    echo "  1 - Install the new kernel modules an DECnet on this system"
    echo "  2 - Pause before install the new kernel and DECnet on this system"
    echo "  3 - Terminate this script"
    read -p "Enter code (1 - 3): " PostBuild junk

    if [ "$Junk" = "" ]; then
	case $PostBuild in
	    1|2|3)
		break
		;;
	esac
    fi
    echo "Invalid Response"
    echo
done

DefaultName=`hostname -s | cut -b1-6`
DefaultAddr="1.1"
DefaultInterface="eth0"

if [ $DECnetConfig -eq 1 ]; then
    echo
    while ${TRUE} ; do
	read -p "Enter your DECnet node address [$DefaultAddr] : " Addr
	if [ -z "$Addr" ]; then
	    Addr=$DefaultAddr
	fi
	check_addr $Addr
	if [ $? -eq 1 ]; then break; fi
    done
    Area=$AreaNo
    Node=$NodeNo

    while ${TRUE} ; do
	read -p "Enter your DECnet node name [$DefaultName] : " Name
	if [ -z "$Name" ]; then
	    Name=$DefaultName
	fi
	check_name $Name
	if [ $? -eq 1 ]; then break; fi
    done

    while ${TRUE} ; do
	read -p "Enter your Ethernet/Wireless interface name [$DefaultInterface] : " Interface
	if [ -z "$Interface" ]; then
	    Interface=$DefaultInterface
	fi
	check_interface $Interface
	if [ $? -eq 1 ]; then break; fi
    done

    ${CP} /dev/null /tmp/node$$

    echo
    echo "You may now set up some other DECnet nodes on your network. When you"
    echo "have finished, press [ENTER] when prompted for the node address."
    echo

    while ${TRUE} ; do
        echo
        while ${TRUE} ; do
            read -p "Enter the node's address: area.node (e.g. 1.1) : " remaddr
            if [ -z "$remaddr" ]; then
                break 2
            fi
            check_addr $remaddr
            if [ $? -eq 1 ]; then break; fi
        done

        while ${TRUE} ; do
            read -p "Enter its node name                            : " remname
            check_name $remname
            if [ $? -eq 1 ]; then break; fi
        done
        printf >>/tmp/nodes$$ "node             %-7s        name            %-6s\n" $remaddr $remname
    done
fi

echo
echo "All questions have been answered"
echo "The download/build log will be in $Log"

start=`$DATE`

echo "DECnet build started at $start\n" > $Log

if [ ${DECnetDownload} -eq 1 ]; then
    DOCMD "cd $Here"
    DOCMD "${RM} -rf LinuxDECnet"
    DOCMD "${GIT} clone https://github.com/JohnForecast/LinuxDECnet"
    if [ $? -ne 0 ]; then
	echo "git failed to clone LinuxDECnet repository"
	exit 1
    fi
fi

if [ ${DECnetDownload} -le 3 ]; then
    cd $Here/LinuxDECnet/kernel

    if [ ${DECnetDownload} -le 2 ]; then
        DOCMD "${MAKE} -C /lib/modules/`uname -r`/build M=${PWD} clean"
    fi
    DOCMD "${MAKE} -C /lib/modules/`uname -r`/build M=${PWD}"

    cd $Here/LinuxDECnet/dnprogs

    if [ ${DECnetDownload} -le 2 ]; then
	DOCMD "${MAKE} clean"
    fi

    DOCMD "${MAKE} all"
    if [ $? -ne 0 ]; then
	echo "DECnet Utilities make failed"
	exit 1
    fi

echo "Kernel module and DECnet Utilities build complete"

case $PostBuild in
    1)
    ;;

    2)
    read -p "Press [ENTER] when ready" Junk
    ;;

    3)
    exit 0
    ;;
esac

fi

DOCMD "cd $Here/LinuxDECnet/kernel"
DOCMD "${MAKE} -C /lib/modules/`uname -r`/build M=${PWD} modules_install"
if [$? -ne 0 ]; then
    echo "Kernel module install failed"
    exit 1
fi

DOCMD "cd $Here/LinuxDECnet/dnprogs"

# Create /usr/include/netdnet if it does not exists and load the 2 default files

if [ ! -d /usr/include/netdnet ]; then
    DOCMD "${MKDIR} /usr/include/netdnet"
    if [ ! -e /usr/include/netdnet/dn.h ]; then
	DOCMD "${CP} include/netdnet/dn.h /usr/include/netdnet"
	if [ $? -ne 0 ]; then
	    echo "Copy of standard header file \'dn.h\' failed"
	    exit 1
	fi
    fi
    if [ ! -e /usr/include/netdnet/dnetdb.h ]; then
	DOCMD "${CP} include/netdnet/dnetdb.h /usr/include/netdnet"
	if [ $? -ne 0 ]; then
	    echo "Copy of standard header file \'dnetdb.h\' failed"
	    exit 1
	fi
    fi
fi

DOCMD "${MAKE} install"
if [ $? -ne 0 ]; then
    echo "DECnet Utilities install failed"
    exit 1
fi

if [ $DECnetConfig -eq 1 ]; then
    ${CAT} >/tmp/$$.conf <<EOF
#V001.0
#               DECnet hosts file
#
#Node           Node            Name            Node    Line    Line
#Type           Address         Tag             Name    Tag     Device
#-----          -------         -----           -----   -----   ------
EOF
    ${PRINTF} >>/tmp/$$.conf "executor         %-7s        name            %-6s  line   %s\n" $Addr $Name $Interface

    ${CAT} /tmp/node$$ >>/tmp/$$.conf
    ${RM} /tmp/node$$
    ${MV} /tmp/$$.conf /etc/decnet.conf
    ${CHMOD} 644 /etc/decnet.conf

# Handle startup logic

    DOCMD "${MKDIR} -p $Here/Startup/systemd"

    NodeAddr=`${EXPR} \( $Area \* 1024 \) + $Node`
    byte4=`${EXPR} $NodeAddr % 256`
    byte5=`${EXPR $NodeAddr / 256`

    ${PRINTF} >/tmp/$$.link "[Match]\n"
    ${PRINTF} >>/tmp/$$.link "OriginalName=%s\n\n" $Interface
    ${PRINTF} >>/tmp/$$.link "[Link]\n"
    ${PRINTF} >>/tmp/$$.link "MacAddress=aa:00:04:00:%02x:%02x\n" $byte4 $byte5
    ${PRINTF} >>/tmp/$$.link "NamePolicy=kernel database onboard slot path\n"

    DOCMD "${MV} /tmp/$$.link $Here/Startup/systemd/00-mac.link"

    ${PRINTF} >/tmp/$$.service "[Unit]\n"
    ${PRINTF} >>/tmp/$$.service "Description=Load DECnet module and start"
    ${PRINTF} >>/tmp/$$.service "\n"
    ${PRINTF} >>/tmp/$$.service "[Service]\n"
    ${PRINTF} >>/tmp/$$.service "Type=oneshot\n"
    ${PRINTF} >>/tmp/$$.service "ExecStartPre=/usr/local/sbin/dnetLoadModule\n"
    ${PRINTF} >>/tmp/$$.service "ExecStart=/usr/local/sbin/dnetd\n"
    ${PRINTF} >>/tmp/$$.service "RemainAfterExit=true\n"
    ${PRINTF} >>/tmp/$$.service "\n"
    ${PRINTF} >>/tmp/$$.service "[Install]\n"
    ${PRINTF} >>/tmp/$$.service "WantedBy=multi-user.target\n"

    DOCMD "${MV} /tmp/$$.service $Here/Startup/systemd/decnet3.service"

    if [ -d /etc/systemd ]; then
	if [ -x ${SYSTEMCTL} ]; then
	    ${SYSTEMCTL} status decnet3.service >/dev/null 2>&1
	    if [ $? -ne 0 ]; then
		for i in /etc/systemd/network/??-mac.link
		do
		    grep "OriginalName=${Interface}" $i /dev/null 2>&1
		    if [ $? -eq 0 ]; then
			MACchange=1
			break
		    fi
		done

		while TRUE ; do
		    echo "This system appears to be using systemd"
		    echo "Do you want systemd to:"
		    if [ ${MACchange} -eq 0 ]; then
		        echo "   Change the MAC address of ${Interface}"
		    fi
		    echo "    Start DECnet running on boot"
		    read -p "Modify systemd settings (Yes/No)? [Yes] " Modify
		    if [ -z "${Modify}" ]; then
		        Modify=Yes
		    fi

		    case $Modify in
			Yes|No)
			    break
			    ;;
		    esac
		    echo "Invalid Response"
		    echo
		done

		if [ "$Modify" = "Yes" ]; then
		    if [ $MACchange -eq 0 ]; then
		        for i in "00" "01" "02" "03" "04" "05" "06" "07" "08" "09"
		        do
			    if [ ! -e /etc/systemd/network/${i}-mac.link ]; then
			        ${CP} $Here/Startup/systemd/00-mac.link /etc/systemd/network/${i}-mac.link
			        break
			    fi
		        done
		    fi
		    ${CP} $Here/systemd/network/decnet3.service /etc/systemd/system
		    ${SYSTEMCTL} daemon-reload
		    ${SYSTEMCTL} decnet3.service
		fi
	    fi
	fi
    fi
fi

echo
echo "Kernel and/or DECnet Utilities successfully installed"
echo
echo "You may still need to decide how to start up DECnet - see section X of"
echo "README.DECnet in $Here/LinuxDECnet"
echo "A reboot is required to change MAC addresses and clear out any"
echo "currently loaded DECnet module"
echo

