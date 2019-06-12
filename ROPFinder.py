import re
from capstone import *
from pwn import *
import sys

# Stergerea gadget-urlior aflate la aceeasi adresa cu ajutorul unui set
def removeDuplicateGadgets(gadgets):
    gadgets_set = set()
    unique_gadgets = []
    for gadget in gadgets:
        addr = gadget["addr"]
        if addr in gadgets_set:
            continue
        gadgets_set.add(addr)
        unique_gadgets += [gadget]
    return unique_gadgets





# Transformarea continutului fisierului dat spre analiza intr-un sir de byte-i
infilename = sys.argv[1]
try:
   file = open(infilename,'rb')
except:
   print("File not found")
   exit()
byteArr = file.read()
file.close()

# Descompunerea fisierului analizat pentru a gasi segmentele executabile
e = ELF(infilename)
binary = bytearray(byteArr)

# Gasirea tuturor segmentelor executabile
segments = e.executable_segments
sections = []

# Preluarea informatiilor necesare pentru fiecare segment intr-un vector de obiecte
for segment in segments :
	sections += [{ "offset" : segment.header.p_offset,
      		       "size" : segment.header.p_memsz,
	               "vaddr" : segment.header.p_vaddr,
	               "opcodes" : bytes(binary[segment.header.p_offset:segment.header.p_offset+segment.header.p_memsz])}]

# Succesiunea de byte-i ce reprezinta instructiuni ret sau derivate ale acesteia, precum si instructiuni pentru apeluri de sistem
# (pentru fiecare gadget se retine si dimensiunea lui) si mnemonicile acestora
normalGadgets = [ [b"\xc3",1],[b"\xc2[\x00-\xff]{2}",3],[b"\xcb",1],[b"\xca[\x00-\xff]{2}",3] ]
sysGadgets = [ [b"\xcd\x80",2], [b"\x0f\x34",2], [b"\x0f\x05",2], [b"\x65\xff\x15\x10\x00\x00\x00",7],[b"\xcd\x80\xc3",3],[b"\x0f\x34\xc3",3], [b"\x0f\x05\xc3",3],[b"\x65\xff\x15\x10\x00\x00\x00\xc3",8] ]
mnemonics  = ["ret", "retf", "int", "sysenter", "syscall"]

gadgets = normalGadgets + sysGadgets

# Initializarea dezasamblorului
md = Cs(CS_ARCH_X86, CS_MODE_32)
goodGadgets = []
# Parsarea vectorului de obiecte ce corespund sectiunilor executabile
for section in sections :
# Preluarea sirului de byte-i ce reprezinta sectiunea
    byteArr = section["opcodes"]
    # Cautarea in seectiune pentru instructiuni care se termina in ret, derivate ale lui ret sau instructiuni de apel de sistem
    for gadget in gadgets:
	potentialRets = []

	# Initializarea expresiei regulate cu ajutorul careia se cauta instructiunile 
        reg = re.compile(gadget[0])
	# Gasirea tuturor pozitiilor din sectiune unde se afla instructiuni folositoare
        for m in reg.finditer(byteArr):
	    potentialRets.append(m.start())
        potentialGadgets = []
        # La fiecare pozitie ma uit in spate 6 pozitii
        for index  in potentialRets:
	    for gadgetSize in range(0,6):
		# Dezasamblarea portiunii analizate si compunerea mnemonicilor gadget-ului
	        gad = ""
		for dec in md.disasm(byteArr[index-gadgetSize:index+gadget[1]],section["vaddr"]+index):
		    gad += (dec.mnemonic + " " + dec.op_str + " ; ").replace("  "," ")
		# Verificare pentru gadget valid
	        if len(gad) > 0:
		   gadins = gad[:-3]
		   instr = gadins.split(" ; ")
	           # Verificare pentru instructiunea folositoare de la sfarsit
            	   if instr[-1].split(" ")[0] not in mnemonics:
			continue
		   # Actualizarea adresei virtuale
		   vaddr = section["vaddr"]+index-gadgetSize
		   # Colectarea gadget-ului alaturi de adresa lui intr-o lista de gadget-uri
		   goodGadgets += [{"gadget" : gad,"addr" : vaddr}]

# Stergerea gadget-urilor care au aceeasi adresa
goodGadgets = removeDuplicateGadgets(goodGadgets)
# Scrierea numarului de gadget-uri
print 'Found', len(goodGadgets), 'gadgets.'
# Scierea gadget-urilor gasite
print "-------------------  Gadgets --------------------"
for gad in goodGadgets:
	print("0x%08x : " % gad["addr"]),
	print(gad["gadget"])


