# LinuxDECnet
DECnet for Linux updated to run on latest Linux kernel (After DECnet code was removed from kertnel 6.1)


README.DECnet

  - Detailed instructions for downloading and installing DECnet on a Linux system.
  
  
BuildAndInstall.sh

  - Shell script which automates most of the process of installing DECnet on a Linux system:
  
  1. Create a working directory on the target system and make that the current directory
  
  2. Copy BuildAndInstall.sh to this directory and make it executable
  
  3. Execute the shell script, answer the questions and wait for a new kernel and DECnet utilities to be built
     (It may take a long time depending on the system configuration)

  4. If BuildAndInstall.sh detects that your installation uses systemd it will create 3 service entries;
     one to change the MAC address of the Ethernet/Wireless LAN interface, the second to load the decnet modules and start it running
     and the third to start the phone daemon running.

  6. If your installation does not use systemd, there are some mechansisms described in the RaspbianDECnet repository about how to get DECnet started (the module name has changed for this respository - "decnet3")
