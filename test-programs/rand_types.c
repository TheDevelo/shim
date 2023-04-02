#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    signed char Vbyte;
    short Vshort;
    int Vint;
    long Vlong;
    unsigned char Vubyte;
    unsigned short Vushort;
    unsigned int Vuint;
    unsigned long Vulong;
    float Vfloat;
    double Vdouble;
    void* Vptr;
    printf("byte addr: %p, short addr: %p, int addr: %p, long addr: %p\n", &Vbyte, &Vshort, &Vint, &Vlong);
    printf("ubyte addr: %p, ushort addr: %p, uint addr: %p, ulong addr: %p\n", &Vubyte, &Vushort, &Vuint, &Vulong);
    printf("float addr: %p, double addr: %p, ptr addr: %p\n", &Vfloat, &Vdouble, &Vptr);

    // Initialize the randomizer
    srand(time(NULL));
    do {
        printf("--- old values ---\n");
        printf("byte: %hhd, short: %hd, int: %d, long: %ld\n", Vbyte, Vshort, Vint, Vlong);
        printf("ubyte: %hhu, ushort: %hu, uint: %u, ulong: %lu\n", Vubyte, Vushort, Vuint, Vulong);
        printf("float: %f, double: %lf, ptr: %p\n", Vfloat, Vdouble, Vptr);
        Vbyte = rand();
        Vshort = rand();
        Vint = rand();
        Vlong = ((long) Vint << 32) + rand();
        Vubyte = rand();
        Vushort = rand();
        Vuint = rand();
        Vulong = ((unsigned long) Vuint << 32) + rand();
        Vfloat = (float) rand() / (float) RAND_MAX * 1024;
        Vdouble = (float) rand() / (float) RAND_MAX * 1024;
        Vptr = (void*) (((unsigned long) rand() << 32) + rand());
        printf("--- new values ---\n");
        printf("byte: %hhd, short: %hd, int: %d, long: %ld\n", Vbyte, Vshort, Vint, Vlong);
        printf("ubyte: %hhu, ushort: %hu, uint: %u, ulong: %lu\n", Vubyte, Vushort, Vuint, Vulong);
        printf("float: %f, double: %lf, ptr: %p\n", Vfloat, Vdouble, Vptr);
    } while (getc(stdin) != EOF);
}
