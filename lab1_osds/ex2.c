#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
	/* Open an executable file here */
    FILE* file = fopen("./bin/dummy", "rb");

    size_t foo_offset = 0x1106;
    size_t foo_size = 78;
    long page_size = getpagesize();

    size_t page_start = (foo_offset / page_size) * page_size;
    size_t offset_into_page = foo_offset - page_start;

    size_t allocation_size = 2 * page_size;

    /* Fill in the details here! */
    void *ptr = mmap(NULL, allocation_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fileno(file), page_start);

    void *code_ptr = (char*)ptr + offset_into_page;

	/* This monster casts ptr to a function pointer with no args and calls it. Basically jumps to your code. */
    (*(void(*)())code_ptr)();

    fclose(file);

    return 0;
}
