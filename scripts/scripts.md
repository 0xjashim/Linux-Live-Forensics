# Linux DFIR Commands



# Dumping Memory

`dd if=/dev/kmem of=/root/kmem` </br>
`dd if=/dev/mem of=/root/mem` </br>
​`sudo insmod ./lime.ko "path=./Linmen.mem format=raw"` </br>
​`./linpmem -o memory.aff4`  </br>
`./linpmem memory.aff4 -e PhysicalMemory -o memory.raw`  </br>

# Taking Image
fdisk -l
dd if=/dev/sda1 of=/[outputlocation]
Misc Useful Tools

# Live Triage

# System Information </br>
`date`</br>
`uname –a`</br> 
`hostname`</br>
`cat /proc/version`</br>
`lsmod`
# Account Information
`cat /etc/passwd` </br>
`cat /etc/shadow`</br>
`cat /etc/sudoers`</br>
`cat /etc/sudoers.d/*`</br>
`cut -d: -f1 /etc/passwd`</br>
`getent passwd | cut -d: -f1`</br>
`compgen -u`</br>
# Current user
`whoami`</br>
`who`</br>
# Last logged on users</br>
`last`</br>
`lastb`</br>
`cat /var/log/auth.log`</br>
# Initialization Files
`cat /etc/bash.bashrc`</br>
`cat ~/.bash_profile` </br>
`cat ~/.bashrc `</br>


# Environment and Startup Programs  </br>
`cat /etc/profile`</br>
`ls /etc/profile.d/`</br>
`cat /etc/profile.d/*`</br>
# Scheduled Tasks
`ls /etc/cron.*`</br>
`ls /etc/cron.*/*`</br>
`cat /etc/cron.*/*`</br>
`cat /etc/crontab`</br>
# SSH Keys and Authorized Users
`cat /etc/ssh/sshd_config`</br>


# Note: This specifies where the SSH daemon will look for keys. Generally this will be as below.
`ls /home/*/.ssh/*`</br>
`cat /home/*/.ssh/id_rsa.pub`</br>
`cat /home/*/.ssh/authorized_keys`</br>
# Sudoers File (who who can run commands as a different user)  </br>
`cat /etc/sudoers`</br>
# Configuration Information
`ls /etc/*.d`</br>
`cat /etc/*.d/*`</br>

# Network Connections / Socket Stats  </br>
`netstat`</br>
`netstat -apetul`</br>
`netstat -plan`</br>
`netstat -plant`</br>
`ss`</br>
`ss -l`</br>
`ss -ta`</br>
`ss -tp`</br>
# IP Table Information
`ls /etc/iptables`</br>
`cat /etc/iptables/*.v4`</br>
`cat /etc/iptables/*.v6`</br>
`iptables -L`</br>

# Network Configuration
`ifconfig -a`</br>

# Browser Plugin Information
`ls -la ~/.mozilla/plugins`</br>
`ls -la /usr/lib/mozilla/plugins`</br>
`ls -la /usr/lib64/mozilla/plugins`</br>
`ls -la ~/.config/google-chrome/Default/Extensions/`</br>
# Kernel Modules and Extensions/
`ls -la /lib/modules/*/kernel/*`</br>

# Process Information  </br>
`ps -s`</br>
`ps -l`</br>
`ps -o`</br>
`ps -t`</br>
`ps -m`</br>
`ps -a`</br>
`top`</br>


# Search files recursively in directory for keyword  </br>
`grep -H -i -r "password" /`</br>
`Process Tree`</br>
`ps -auxwf`</br>
# Open Files and space usage
`lsof`</br>
`du`</br>

# Pluggable Authentication Modules (PAM)  </br>
`cat /etc/pam.d/sudo`</br>
`cat /etc/pam.conf`</br>
`ls /etc/pam.d/`</br>


# Disk / Partition Information
`fdisk -l​`</br>
`strace -f -e trace=network -s 10000 <PROCESS WITH ARGUMENTS>;`</br>
`strace -f -e trace=network -s 10000 -p <PID>;`</br>


# Detailed Process Information
`ls -al /proc/[PID]` </br>
`CWD = Current Working Directory of Malware`</br>
`EXE = Binary location and whether it has been deleted`</br>


# Recover deleted binary which is currently running </br>

`cp /proc/[PID]/exe /[destination]/[binaryname]`
# Capture Binary Data for Review  </br>
`cp /proc/[PID]/ /[destination]/[PID]/`

# Binary hash information  </br>
`sha1sum /[destination]/[binaryname]`</br>
md5sum /[destination]/[binaryname] </br>

# Process Command Line Information
`cat /proc/[PID]/cmdline`</br>
`cat /proc/[PID]/comm`</br>

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
# Deleted binaries which are still running  </br>
ls -alr /proc/*/exe 2> /dev/null |  grep deleted  </br>
# Process Working Directories (including common targeted directories)  </br>
`ls -alr /proc/*/cwd` </br>
`ls -alr /proc/*/cwd 2> /dev/null | grep tmp` </br>
`ls -alr /proc/*/cwd 2> /dev/null | grep dev` </br>
`ls -alr /proc/*/cwd 2> /dev/null | grep var` </br>
`ls -alr /proc/*/cwd 2> /dev/null | grep home` </br>
# Hidden Directories and Files </br>
`find / -type d -name ".*"` </br>
# Immutable Files and Directories (Often Suspicious) </br>
`lsattr / -R 2> /dev/null | grep "\----i"` </br>
# SUID/SGID and Sticky Bit Special Permissions  </br>
`find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \;` </br>
# File and Directories with no user/group name  </br>
`find / \( -nouser -o -nogroup \) -exec ls -lg  {} \;`
# File types in current directory  </br>
`file * -p`
# Executables on file system </br>
`find / -type f -exec file -p '{}' \; |  grep ELF` </br>
# Hidden Executables on file system </br>
`find / -name ".*" -exec file -p '{}' \; | grep ELF`
# Files modified within the past day </br>
`find / -mtime -1`
# Persistent Areas of Interest </br>
`/etc/rc.local` </br>
`/etc/initd` </br>
`/etc/rc*.d` </br>
`/etc/modules` </br>
`/etc/cron*`</br>
`/etc/cron*`</br>
`/etc/cron*`</br>
`/var/spool/cron/*`</br>
`/usr/lib/cron/`</br>
`/usr/lib/cron/tabs`</br>
# Audit Logs </br>
`ls -al /var/log/*`</br>
`ls -al /var/log/*tmp`</br>
`utmpdump /var/log/btmp`</br>
`utmpdump /var/run/utmp`</br>
`utmpdump /var/log/wtmp`</br>
# Installed Software Packages </br>
`ls /usr/bin/`</br>
`ls /usr/local/bin/`</br>
