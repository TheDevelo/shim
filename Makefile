all: shim

shim: build/main.o build/commands.o
	cc -o shim build/main.o build/commands.o

build/main.o: main.c
	cc -c -o build/main.o main.c

build/commands.o: commands.c
	cc -c -o build/commands.o commands.c

clean:
	rm -rf build
	rm -f shim
	mkdir build
