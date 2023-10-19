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
DEPMOD=/sbin/depmod
EXPR=/usr/bin/expr
GIT=/usr/bin/git
GREP=/bin/grep
MAKE=/usr/bin/make
MV=/bin/mv
PRINTF=/usr/bin/printf
PWD=/bin/pwd
RM=/bin/rm
TR=/usr/bin/tr
TRUE=/bin/true

# ip, mkdir, systemctl and uname seem to move around:
#    - debian they are at /usr/bin, ubuntu at /bin
IP=/usr/sbin/ip
MKDIR=/usr/bin/mkdir
SYSTEMCTL=/usr/bin/systemctl
UNAME=/usr/bin/uname
if [ -x /bin/ip ]; then
    IP=/bin/ip
fi
if [ -x /bin/mkdir ]; then
    MKDIR=/bin/mkdir
fi
if [ -x /bin/systemctl ]; then
    SYSTEMCTL=/bin/systemctl
fi
if [ -x /bin/uname ]; then
    UNAME=/bin/uname
fi

# Debian tools
APT=/usr/bin/apt
APTGET=/usr/bin/apt-get
DPKG=/usr/bin/dpkg

# Fedora tools
DNF=/usr/bin/dnf
YUM=/usr/bin/yum

Here=`${PWD}`
Log=${Here}/Log

CPUtype=`${UNAME} -m`

DECnetDownload=1
DECnetConfig=1
Pause=1

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

# Determine if SELinux is installed and running in "Enforcing" mode

SESTATUS=`which sestatus`
if [ ! -z "${SESTATUS}" ]; then
    ${SESTATUS} | ${GREP} "SELinux status" | ${GREP} "enabled" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
	${SESTATUS} | ${GREP} "Current mode" | ${GREP} "enforcing" >/dev/null 2>&1
	if [ $? -eq 0 ]; then
	    while ${TRUE} ; do
	        echo "SELinux is installed on this system and running in 'Enforcing' mode. DECnet"
	        echo "will only be able run on this system if you change the mode to 'permissive'"
	        echo "or 'disabled'"
		echo

	        read -p "Do you want to continue (Yes/No)? [Yes] " Cont
	        if [ -z "${Cont}" ]; then
	            Cont=Yes
	        fi

	        case ${Cont} in
		    [Yy]es|[Nn]o)
			break
		        ;;
	        esac
	        echo "Invalid Response"
	        echo
	    done
	
	    if [ "${Cont}" = "No" -o "${Cont}" = "no" ]; then
	        exit 0
	    fi	
	fi
    fi
fi

#
# Determine if we support this particular distribution
#

check_supported_os() {
    if [ "${HAVE_PACKAGES}" != "1" ]; then
	test -e /etc/os-release && os_release='/etc/os-release'
	if [ -z "${os_release}" ]; then
	    test -e /usr/lib/os-release && os_release='/usr/lib/os-release'
	    if [ -z "${os_release}" ]; then
		echo "Unable to determine which distribution is installed on"
		echo "this system. Manually install the following packages and"
		echo "re-run this script with the 'HAVE_PACKAGES=1' override."
		echo
		echo "  gcc g++ git iproute2 libssl-dev make linux-libc-dev"
		echo "  libncurses-dev"
		echo
		echo "along with any packages this directibution needs for"
		echo "kernel module development"
		echo
		exit 1
	    fi
	fi

	source ${os_release}

	OS_list="${ID} ${ID_LIKE}"

	for os in ${OS_list}
	do
	    case ${os} in
		raspbian|debian)
		    PKGLIST="xz-utils gcc g++ git iproute2 libssl-dev make linux-libc-dev libncurses-dev libreadline-dev"
		    OStype=debian
		    return 0
		;;

		fedora)
		    PKGLIST="gcc gcc-c++ git iproute openssl-devel make glibc-devel ncurses-devel readline-devel"
		    OStype=fedora

		    if [ -x ${DNF} ]; then
			INST=${DNF}
			return 0
		    fi
		    if [ -x ${YUM} ]; then
			INST=${YUM}
			return 0;
		    fi
		    echo "An executable DNF or YUM is not installed on this"
		    echo "system. Unable to proceed."
		    exit 1
		    ;;
	    esac
	done

	echo "This system is running the " ${ID} " distribution which is not"
	echo "supported by this script. You can try manually installing the"
	echo "following packages and re-run this script with the"
	echo "'HAVE_PACKAGES=1' override."
	echo
	echo "  gcc g++ git iproute2 libssl-dev make linux-libc-dev"
	echo "  libncurses-dev"
	echo
	echo "along with any packages this directibution needs for"
	echo "kernel module development"
	echo
	exit 1
    fi
}

#
# Useful functions
#
check_addr() {
    if [ ! -z "$1" ]; then
        if [ `${EXPR} $1 : '[0-9]*\.[0-9]*'` -ne "`${EXPR} length $1`" ]; then
            echo "Node address must be in the format area.node"
            return 0
        fi

        AreaNo=`echo $1 | ${CUT} -d. -f1`
        NodeNo=`echo $1 | ${CUT} -d. -f2`

        if [ "${AreaNo}" -le 0 -o "${AreaNo}" -ge 64 ]; then
            echo "Area must be between 1 and 63 inclusive"
            return 0
        fi

        if [ "${NodeNo}" -le 0 -o "${NodeNo}" -ge 1024 ]; then
            echo "Node must be between 1 and 1023 inclusive"
            return 0
        fi
        return 1
    fi
    return 0
}

check_name() {
    if [ "`${EXPR} length "$1"`" -le 6 ]; then
        if [ `${EXPR} "$1" : '[0-9a-zA-Z]*'` -ne "`${EXPR} length "$1"`" ]; then
            echo "DECnet node names may be up to 6 alphanumeric characters"
            return 0
        fi
	if [ `${EXPR} "$1" : '[0-9]*'` -eq "`${EXPR} length "$1"`" ]; then
	    echo "DECnet node names must include at least 1 alpha character"
	    return 0
	fi
        return 1
    fi
    return 0
}

check_interface() {
    ${GREP} -q "$1:" /proc/net/dev
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

set_default_interface() {
    DefaultInterface=`${IP} link | ${GREP} -m1 BROADCAST | cut -d ' ' -f2 | tr -d ':'`
}

#

check_headers() {
    if [ "${HAVE_HEADERS}" = "1" ]; then
	if [ -d /lib/modules/$(uname -r)/source/include ]; then
	    return
	fi
    fi

    case ${OStype} in
	debian)
	    if [ -x ${APT} ]; then
		${APT} list 2>/dev/null | ${GREP} raspberrypi-kernel-headers >/dev/null 2>&1
		if [ $? -eq 0 ]; then
		    PKGLIST="${PKGLIST} raspberrypi-kernel-headers"
		    return
		fi
	    fi
	    PKGLIST="${PKGLIST} linux-headers-$(uname -r)"
	    ;;

	fedora)
	    if [ "${CPUtype}" = "aarch64" ]; then
		PKGLIST="${PKGLIST} kernel-devel-$(uname -r)"
	    else
		PKGLIST="${PKGLIST} kernel-devel"
	    fi
	    ;;
    esac
}

check_installed_packages() {
    echo "Checking required packages are installed..."

    case ${OStype} in
	debian)
	    if [ -x ${APTGET} -a -x ${DPKG} ]; then
		for pkg in ${PKGLIST}
		do
		    ${DPKG} -s ${pkg} >/dev/null 2>&1
		    if [ $? -ne 0 ]; then
			echo -n "Installing ${pkg} ..."
			${APTGET} install -y ${pkg} >/dev/null 2>&1
			if [ $? -ne 0 ]; then
			    echo "Failed to install package '" ${pkg} "'"
			    exit 1
			fi
			echo
		    fi
		done
		return 1
	    fi
	    ;;

	fedora)
	    for pkg in ${PKGLIST}
	    do
		${INST} list installed ${pkg} >/dev/null 2>&1
		if [ $? -ne 0 ]; then
		    echo -n "Installing ${pkg} ..."
		    ${INST} install -y ${pkg} >/dev/null 2>&1
		    if [ $? -ne 0 ]; then
			echo "Failed to install package '" ${pkg} "'"
			exit 1
		    fi
		    echo
		fi
	    done
	    return 1
	    ;;
    esac
    return 0
}

check_supported_os

# Make sure that all required packages are installed

if [ "${HAVE_PACKAGES}" != "1" ]; then
    check_headers

    check_installed_packages
    if [ $? -eq 0 ]; then
	echo "Invalid OStype value ... terminating install"
	exit 1
    fi
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

	if [ "${Junk}" = "" ]; then
	    case ${DECnetDownload} in
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

	if [ "${Junk}" = "" ]; then
	    case ${DECnetConfig} in
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
    echo "  1 - Install the new kernel modules and DECnet on this system"
    echo "  2 - Pause before install the new kernel and DECnet on this system"
    echo "  3 - Terminate this script"
    read -p "Enter code (1 - 3): " PostBuild junk

    if [ "${Junk}" = "" ]; then
	case ${PostBuild} in
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
set_default_interface

if [ ${DECnetConfig} -eq 1 ]; then
    echo
    while ${TRUE} ; do
	read -p "Enter your DECnet node address [${DefaultAddr}] : " Addr
	if [ -z "${Addr}" ]; then
	    Addr=${DefaultAddr}
	fi
	check_addr ${Addr}
	if [ $? -eq 1 ]; then break; fi
    done
    Area=${AreaNo}
    Node=${NodeNo}

    while ${TRUE} ; do
	read -p "Enter your DECnet node name [${DefaultName}] : " MyName
	if [ -z "${MyName}" ]; then
	    MyName=${DefaultName}
	fi
	check_name ${MyName}
	if [ $? -eq 1 ]; then break; fi
    done

    Name=`echo -n ${MyName} | ${TR} "[:lower:]" "[:upper:]"`

    while ${TRUE} ; do
	read -p "Enter your Ethernet/Wireless interface name [${DefaultInterface}] : " Interface
	if [ -z "${Interface}" ]; then
	    Interface=${DefaultInterface}
	fi
	check_interface ${Interface}
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
            if [ -z "${remaddr}" ]; then
                break 2
            fi
            check_addr ${remaddr}
            if [ $? -eq 1 ]; then break; fi
        done

        while ${TRUE} ; do
            read -p "Enter its node name                            : " remname
            check_name ${remname}
            if [ $? -eq 1 ]; then break; fi
        done

	remname=`echo -n ${remname} | ${TR} "[:lower:]" "[:upper"]"`

        printf >>/tmp/node$$ "node             %-7s        name            %-6s\n" ${remaddr} ${remname}
    done
fi

echo
echo "All questions have been answered"
echo "The download/build log will be in ${Log}"

start=`${DATE}`

echo "DECnet build started at ${start}\n" > ${Log}

if [ ${DECnetDownload} -eq 1 ]; then
    DOCMD "cd ${Here}"
    DOCMD "${RM} -rf LinuxDECnet"
    DOCMD "${GIT} clone https://github.com/JohnForecast/LinuxDECnet"
    if [ $? -ne 0 ]; then
	echo "git failed to clone LinuxDECnet repository"
	exit 1
    fi
fi

if [ ${DECnetDownload} -le 3 ]; then
    cd ${Here}/LinuxDECnet/kernel

    if [ ${DECnetDownload} -le 2 ]; then
        DOCMD "${MAKE} -C /lib/modules/`uname -r`/build M=${PWD} clean"
    fi
    DOCMD "${MAKE} -C /lib/modules/`uname -r`/build M=${PWD}"
    if [ $? -ne 0 ]; then
	echo "DECnet kernel module make failed"
	exit 1
    fi

    cd ${Here}/LinuxDECnet/dnprogs

    if [ ${DECnetDownload} -le 2 ]; then
	DOCMD "${MAKE} clean"
    fi

    DOCMD "${MAKE} all"
    if [ $? -ne 0 ]; then
	echo "DECnet Utilities make failed"
	exit 1
    fi

echo "Kernel module and DECnet Utilities build complete"

case ${PostBuild} in
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

DOCMD "cd ${Here}/LinuxDECnet/kernel"
DOCMD "${MAKE} -C /lib/modules/`uname -r`/build M=${PWD} modules_install"
if [ $? -ne 0 ]; then
    echo "Kernel module install failed"
    exit 1
fi
DOCMD "${DEPMOD} -A"

DOCMD "cd ${Here}/LinuxDECnet/dnprogs"

DOCMD "${MAKE} install"
if [ $? -ne 0 ]; then
    echo "DECnet Utilities install failed"
    exit 1
fi

if [ ${DECnetConfig} -eq 1 ]; then
    ${CAT} >/tmp/$$.conf <<EOF
#V001.0
#               DECnet hosts file
#
#Node           Node            Name            Node    Line    Line
#Type           Address         Tag             Name    Tag     Device
#-----          -------         -----           -----   -----   ------
EOF
    ${PRINTF} >>/tmp/$$.conf "executor         %-7s        name            %-6s  line   %s\n" ${Addr} ${Name} ${Interface}

    ${CAT} /tmp/node$$ >>/tmp/$$.conf
    ${RM} /tmp/node$$
    ${MV} /tmp/$$.conf /etc/decnet.conf
    ${CHMOD} 644 /etc/decnet.conf

# Handle startup logic

    cd ${Here}/LinuxDECnet/dnprogs/dnetd
    dnetd_locn=`make -s location | tr -d "\n"`
    cd ${Here}/LinuxDECnet/dnprogs/scripts
    scripts_locn=`make -s location | tr -d "\n"`

    DOCMD "${MKDIR} -p ${Here}/Startup/systemd"

    ${PRINTF} >/tmp/$$.service "[Unit]\n"
    ${PRINTF} >>/tmp/$$.service "Description=Change MAC address for DECnet device\n"
    ${PRINTF} >>/tmp/$$.service "Wants=network-pre.target\n"
    ${PRINTF} >>/tmp/$$.service "Before=network-pre.target\n"
    ${PRINTF} >>/tmp/$$.service "\n"
    ${PRINTF} >>/tmp/$$.service "[Service]\n"
    ${PRINTF} >>/tmp/$$.service "Type=oneshot\n"
    ${PRINTF} >>/tmp/$$.service "ExecStart=${scripts_locn}/sbin/dnetChangeMAC\n"
    ${PRINTF} >>/tmp/$$.service "\n"
    ${PRINTF} >>/tmp/$$.service "[Install]\n"
    ${PRINTF} >>/tmp/$$.service "WantedBy=multi-user.target\n"

    DOCMD "${MV} /tmp/$$.service ${Here}/Startup/systemd/DECnetMAC.service"

    ${PRINTF} >/tmp/$$.service "[Unit]\n"
    ${PRINTF} >>/tmp/$$.service "Description=Load DECnet module and start\n"
    ${PRINTF} >>/tmp/$$.service "After=network.target\n"
    ${PRINTF} >>/tmp/$$.service "\n"
    ${PRINTF} >>/tmp/$$.service "[Service]\n"
    ${PRINTF} >>/tmp/$$.service "Type=oneshot\n"
    ${PRINTF} >>/tmp/$$.service "ExecStartPre=${scripts_locn}/sbin/dnetLoadModule\n"
    ${PRINTF} >>/tmp/$$.service "ExecStart=${dnetd_locn}/sbin/dnetd\n"
    ${PRINTF} >>/tmp/$$.service "RemainAfterExit=true\n"
    ${PRINTF} >>/tmp/$$.service "\n"
    ${PRINTF} >>/tmp/$$.service "[Install]\n"
    ${PRINTF} >>/tmp/$$.service "WantedBy=multi-user.target\n"

    DOCMD "${MV} /tmp/$$.service $Here/Startup/systemd/decnet3.service"

    if [ -d /etc/systemd ]; then
	if [ -x ${SYSTEMCTL} ]; then
	    ${SYSTEMCTL} status decnet3.service >/dev/null 2>&1
	    if [ $? -ne 0 ]; then
		while ${TRUE} ; do
		    echo "This system appears to be using systemd"
		    echo "Do you want systemd to:"
		    echo "   Change the MAC address of ${Interface}"
		    echo "    Start DECnet running on boot"

		    read -p "Modify systemd settings (Yes/No)? [Yes] " Modify
		    if [ -z "${Modify}" ]; then
		        Modify=Yes
		    fi

		    case ${Modify} in
			[Yy]es|[Nn]o)
			    break
			    ;;
		    esac
		    echo "Invalid Response"
		    echo
		done

		if [ "${Modify}" = "Yes" -o "${Modify}" = "yes" ]; then
		    ${SYSTEMCTL} disable DECnetMAC.service >/dev/null 2>&1
		    ${SYSTEMCTL} disable decnet3.service >/dev/null 2>&1

		    ${CP} ${Here}/Startup/systemd/DECnetMAC.service /etc/systemd/system
		    ${CP} ${Here}/Startup/systemd/decnet3.service /etc/systemd/system
		    ${SYSTEMCTL} daemon-reload
		    ${SYSTEMCTL} enable DECnetMAC.service >/dev/null
		    ${SYSTEMCTL} enable decnet3.service >/dev/null
		fi
	    fi
	fi
    fi
fi

echo
echo "Kernel and/or DECnet Utilities successfully installed"
echo
echo "You may still need to decide how to start up DECnet - see section X of"
echo "README.DECnet in ${Here}/LinuxDECnet"
echo "A reboot is required to change MAC addresses and clear out any"
echo "currently loaded DECnet module"
echo

