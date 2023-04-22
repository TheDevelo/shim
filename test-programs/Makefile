all: random line_reader dense_mm string_write rand_types segfault

random: random.c
	cc -o build/random random.c

line_reader: line_reader.c
	cc -o build/line_reader line_reader.c

dense_mm: dense_mm.c
	cc -o build/dense_mm dense_mm.c

string_write: string_write.c
	cc -o build/string_write string_write.c

rand_types: rand_types.c
	cc -o build/rand_types rand_types.c

segfault: segfault.c
	cc -o build/segfault segfault.c

clean:
	rm -rf build
	mkdir build
