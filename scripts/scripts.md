# Linux DFIR Commands



# Dumping Memory


`dd if=/dev/kmem of=/root/kmem` </br>
`dd if=/dev/mem of=/root/mem` </br>
​`sudo insmod ./lime.ko "path=./Linmen.mem format=raw"` </br>
​
​
`./linpmem -o memory.aff4`
`./linpmem memory.aff4 -e PhysicalMemory -o memory.raw`

# Taking Image
fdisk -l
dd if=/dev/sda1 of=/[outputlocation]
Misc Useful Tools

# Live Triage

# System Information

`date`  
`uname –a`  
hostname
cat /proc/version
lsmod
Account Information
cat /etc/passwd
cat /etc/shadow
cat /etc/sudoers
cat /etc/sudoers.d/*
cut -d: -f1 /etc/passwd
getent passwd | cut -d: -f1
compgen -u
Current user
whoami
who
Last logged on users
last
lastb
cat /var/log/auth.log
Initialization Files
cat /etc/bash.bashrc
cat ~/.bash_profile 
cat ~/.bashrc `


# Environment and Startup Programs

cat /etc/profile
ls /etc/profile.d/
cat /etc/profile.d/*
Scheduled Tasks
ls /etc/cron.*
ls /etc/cron.*/*
cat /etc/cron.*/*
cat /etc/crontab
SSH Keys and Authorized Users
cat /etc/ssh/sshd_config


# Note: This specifies where the SSH daemon will look for keys. Generally this will be as below.
ls /home/*/.ssh/*
cat /home/*/.ssh/id_rsa.pub
cat /home/*/.ssh/authorized_keys
Sudoers File (who who can run commands as a different user)
cat /etc/sudoers
Configuration Information
ls /etc/*.d
cat /etc/*.d/*

# Network Connections / Socket Stats

netstat
netstat -apetul
netstat -plan
netstat -plant
ss
ss -l
ss -ta
ss -tp
IP Table Information
ls /etc/iptables
cat /etc/iptables/*.v4
cat /etc/iptables/*.v6
iptables -L

# Network Configuration
ifconfig -a

# Browser Plugin Information
ls -la ~/.mozilla/plugins
ls -la /usr/lib/mozilla/plugins
ls -la /usr/lib64/mozilla/plugins
ls -la ~/.config/google-chrome/Default/Extensions/
Kernel Modules and Extensions/
ls -la /lib/modules/*/kernel/*

# Process Information
ps -s
ps -l
ps -o
ps -t
ps -m
ps -a
top


# Search files recursively in directory for keyword

grep -H -i -r "password" /
Process Tree
ps -auxwf
Open Files and space usage
lsof
du

# Pluggable Authentication Modules (PAM)
cat /etc/pam.d/sudo
cat /etc/pam.conf
ls /etc/pam.d/


# Disk / Partition Information
fdisk -l​
strace -f -e trace=network -s 10000 <PROCESS WITH ARGUMENTS>;
strace -f -e trace=network -s 10000 -p <PID>;

# Note: Below material with thanks to 
​
Detailed Process Information
ls -al /proc/[PID]
Note:
CWD = Current Working Directory of Malware
EXE = Binary location and whether it has been deleted

Most Common Timestamp = When process was created

Recover deleted binary which is currently running
cp /proc/[PID]/exe /[destination]/[binaryname]
Capture Binary Data for Review
cp /proc/[PID]/ /[destination]/[PID]/
Binary hash information
sha1sum /[destination]/[binaryname]
md5sum /[destination]/[binaryname]
Process Command Line Information
cat /proc/[PID]/cmdline
cat /proc/[PID]/comm
Note:

Significant differences in the above 2 outputs and the specified binary name under /proc/[PID]/exe can be indicative of malicious software attempting to remain undetected.

Process Environment Variables (incl user who ran binary)
strings /proc/[PID]/environ
cat /proc/[PID]/environ
Process file descriptors/maps (what the process is ‘accessing’ or using)
ls -al /proc/[PID]/fd
cat /proc/[PID]/maps
Process stack/status information (may reveal useful elements)
cat /proc/[PID]/stack
cat /proc/[PID]/status
Deleted binaries which are still running
ls -alr /proc/*/exe 2> /dev/null |  grep deleted
Process Working Directories (including common targeted directories)
ls -alr /proc/*/cwd
ls -alr /proc/*/cwd 2> /dev/null | grep tmp
ls -alr /proc/*/cwd 2> /dev/null | grep dev
ls -alr /proc/*/cwd 2> /dev/null | grep var
ls -alr /proc/*/cwd 2> /dev/null | grep home
Hidden Directories and Files
find / -type d -name ".*"
Immutable Files and Directories (Often Suspicious)
lsattr / -R 2> /dev/null | grep "\----i"
SUID/SGID and Sticky Bit Special Permissions
find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \;
File and Directories with no user/group name
find / \( -nouser -o -nogroup \) -exec ls -lg  {} \;
File types in current directory
file * -p
Executables on file system
find / -type f -exec file -p '{}' \; |  grep ELF
Hidden Executables on file system
find / -name ".*" -exec file -p '{}' \; | grep ELF
Files modified within the past day
find / -mtime -1
Persistent Areas of Interest
/etc/rc.local
/etc/initd
/etc/rc*.d
/etc/modules
/etc/cron*
/var/spool/cron/*
/usr/lib/cron/
/usr/lib/cron/tabs
Audit Logs
ls -al /var/log/*
ls -al /var/log/*tmp
utmpdump /var/log/btmp
utmpdump /var/run/utmp
utmpdump /var/log/wtmp
Installed Software Packages
ls /usr/bin/
ls /usr/local/bin/
