# LinuxDECnet
DECnet for Linux updated to run on latest Linux kernel


README.DECnet

  - Detailed instructions for downloading and installing DECnet on a Linux system.
  
  
BuildAndInstall.sh

  - Shell script which automates most of the process of installing DECnet on a Linux system:
  
  1. Create a working directory on the target system and make that the current directory
  
  2. Copy BuildAndInstall.sh to this directory and make it executable
  
  3. Execute the shell script, answer the questions and wait for a new kernel and DECnet utilities to be built
     (It may take a long time depending on the system configuration)
     
  4. After installing a new kernel and the DECnet utilities, you will need to decide how and when you want DECnet
     to start (see section 6 of README.DECnet for details).

