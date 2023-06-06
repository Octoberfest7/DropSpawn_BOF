all:
	i686-w64-mingw32-gcc -o dist/dropspawn.x86.o -Os -c src/DropSpawn_BOF/main.c -lshlwapi
	x86_64-w64-mingw32-gcc -o dist/dropspawn.x64.o -Os -c src/DropSpawn_BOF/main.c -lshlwapi