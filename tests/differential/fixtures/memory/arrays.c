#include "streams.h"
#include <stdlib.h>
#include <string.h>

struct Cell {
    unsigned byte;
    unsigned weight;
};

__attribute__((noinline)) static void copy_products(const struct Cell* cell, unsigned* dest,
                                                    size_t count) {
    for (size_t i = 0; i < count; ++i, ++cell)
        dest[i] = cell->byte * cell->weight;
}

int main(int argc, char** argv) {
    if (!open_binary_streams() || argc != 2)
        return 2;
    struct Cell cells[8];
    const size_t count = strlen(argv[1]);
    if (count == 0 || count > sizeof(cells) / sizeof(cells[0]))
        return 2;
    for (size_t i = 0; i < count; ++i)
        cells[i] = (struct Cell){(unsigned char)argv[1][i], (unsigned)i + 1};

    unsigned* products = malloc(count * sizeof(*products));
    if (!products)
        return 1;
    copy_products(cells, products, count);
    unsigned sum = 0;
    for (size_t i = 0; i < count; ++i)
        sum += products[i];
    free(products);
    printf("sum=%u\n", sum);
    return 0;
}
