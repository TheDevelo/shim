all: random line_reader dense_mm string_write rand_types segfault

random: random.c
	cc -g -o build/random random.c

line_reader: line_reader.c
	cc -g -o build/line_reader line_reader.c

dense_mm: dense_mm.c
	cc -g -o build/dense_mm dense_mm.c

string_write: string_write.c
	cc -g -o build/string_write string_write.c

rand_types: rand_types.c
	cc -g -o build/rand_types rand_types.c

segfault: segfault.c
	cc -g -o build/segfault segfault.c

clean:
	rm -rf build
	mkdir build
