cc-args = -O3

all: shim

shim: build/main.o build/commands.o build/helpers.o
	cc $(cc-args) -o shim build/main.o build/commands.o build/helpers.o

build/main.o: main.c
	cc -c $(cc-args) -o build/main.o main.c

build/commands.o: commands.c
	cc -c $(cc-args) -o build/commands.o commands.c

build/helpers.o: helpers.c
	cc -c $(cc-args) -o build/helpers.o helpers.c

clean:
	rm -rf build
	rm -f shim
	mkdir build
