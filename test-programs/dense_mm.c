/******************************************************************************
* 
* dense_mm.c
* 
* This program implements a dense matrix multiply and can be used as a
* hypothetical workload. 
*
* Usage: This program takes a single input describing the size of the matrices
*        to multiply. For an input of size N, it computes A*B = C where each
*        of A, B, and C are matrices of size N*N. Matrices A and B are filled
*        with random values. 
*
* Written Sept 6, 2015 by David Ferry
******************************************************************************/

#include <stdio.h>  //For printf()
#include <stdlib.h> //For exit() and atoi()
#include <time.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/time.h>

const int num_expected_args = 2;
const unsigned sqrt_of_UINT32_MAX = 65536;

// From GNU documentation for subtracting timevals
int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
    /* Perform the carry for the later subtraction by updating y. */
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait. tv_usec is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}

int main( int argc, char* argv[] ){
    unsigned index, row, col; //loop indicies
    unsigned matrix_size, squared_size;
    double *A, *B, *C;

    if (argc != num_expected_args) {
        printf("Usage: ./dense_mm <size of matrices>\n");
        exit(-1);
    }

    matrix_size = atoi(argv[1]);

    if (matrix_size > sqrt_of_UINT32_MAX) {
        printf("ERROR: Matrix size must be between zero and 65536!\n");
        exit(-1);
    }

    squared_size = matrix_size * matrix_size;
    A = (double*) malloc( sizeof(double) * squared_size );
    B = (double*) malloc( sizeof(double) * squared_size );
    C = (double*) malloc( sizeof(double) * squared_size );

    printf("dense_mm matrix multiply\n");
    printf("matrix locations - A: %p, B: %p, C: %p\n", A, B, C);

    while (getc(stdin) != EOF) {
        printf("Generating matrices...\n");

        for( index = 0; index < squared_size; index++ ){
            A[index] = (double) rand();
            B[index] = (double) rand();
            C[index] = 0.0;
        }

        printf("Multiplying matrices...\n");

        struct timeval time1, time2, result;
        gettimeofday(&time1, NULL);

        for( col = 0; col < matrix_size; col++ ){
            for( row = 0; row < matrix_size; row++ ){
                for( index = 0; index < matrix_size; index++){
                C[row*matrix_size + col] += A[row*matrix_size + index] *B[index*matrix_size + col];
                }
            }
        }

        gettimeofday(&time2, NULL);
        printf("Multiplication done\n");
        timeval_subtract(&result, &time2, &time1);
        printf("Time taken: %ld.%06ld\n", result.tv_sec, result.tv_usec);

    }

    free(A);
    free(B);
    free(C);

    return 0;
}
