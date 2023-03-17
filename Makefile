all: shim

shim: build/main.o build/commands.o build/helpers.o
	cc -g -o shim build/main.o build/commands.o build/helpers.o

build/main.o: main.c
	cc -g -c -o build/main.o main.c

build/commands.o: commands.c
	cc -g -c -o build/commands.o commands.c

build/helpers.o: helpers.c
	cc -g -c -o build/helpers.o helpers.c

clean:
	rm -rf build
	rm -f shim
	mkdir build
