# Basic System

Basic use case: you have a general group called `nasusers`, with access to most shares, and a group called `finance` with access to restricted information.

## Share Layout and Permissions

Assuming Samba is setup to provide shares in the `/shares/` directory, create initial directories as follows

```
# ls -al /shares/
total 20
drwxrwsr-x  5 root nasusers 4096 Feb  9 12:59 .
drwxr-xr-x 24 root root     4096 Feb  9 12:56 ..
drwxrws---  2 root nasusers 4096 Feb  9 13:01 general
drwxrws---  2 root finance  4096 Feb  9 13:01 finance
```

And set permissions as follows
```
chown root:nasusers /shares
chmod 2775 /shares
chmod 2770 /shares/general /shares/finance
chgrp -R nasusers /shares/general
chgrp -R finance /shares/finance
```

## smb.conf

The following simplified `smb.conf` will enable ACLs and prevent users from seeing directories or files where they are not a member of the group.

```
[global]
   workgroup = WORKGROUP
   server string = %h server (Samba, Ubuntu)
;   interfaces = 127.0.0.0/8 eth0
;   bind interfaces only = yes
   log file = /var/log/samba/log.%m
   max log size = 1000
   logging = file
   panic action = /usr/share/samba/panic-action %d

   server role = standalone server
   obey pam restrictions = yes
   unix password sync = yes
   passwd program = /usr/bin/passwd %u
   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .
   pam password change = yes
   map to guest = bad user
   usershare allow guests = no
   # Important for POSIX-style permissions
   unix extensions = yes

   aio read size = 16384
   aio write size = 16384

   min receivefile size = 16384
   getwd cache = true

   oplocks = yes
   level2 oplocks = yes

#======================= Share Definitions =======================

[shares]
   comment = Company Shares
   path = /shares

   browseable = yes
   read only = no

   # CRITICAL: visibility control
   hide unreadable = yes
   #hide unwriteable files = yes

   # Correct permission inheritance
   create mask = 0660
   force create mode = 0660
   directory mask = 2770
   force directory mode = 2770
   inherit permissions = yes
   inherit acls = yes

   # CRITICAL: stop DOS attribute → exec-bit weirdness
   store dos attributes = yes
   map archive = no
   map system = no
   map hidden = no
```