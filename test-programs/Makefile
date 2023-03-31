all: random line_reader dense_mm

random: random.c
	cc -o build/random random.c

line_reader: line_reader.c
	cc -o build/line_reader line_reader.c

dense_mm: dense_mm.c
	cc -o build/dense_mm dense_mm.c

clean:
	rm -rf build
	mkdir build
