all: shim

shim: build/main.o build/commands.o
	cc -g -o shim build/main.o build/commands.o

build/main.o: main.c
	cc -g -c -o build/main.o main.c

build/commands.o: commands.c
	cc -g -c -o build/commands.o commands.c

clean:
	rm -rf build
	rm -f shim
	mkdir build
