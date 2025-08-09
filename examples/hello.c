#include <stdio.h>

void short_func() {
    printf("Hello world!\n");
}

void long_func() {
    int i = 0;
    goto end; // bad: should be caught
    // artificially long body
    for (i = 0; i < 60; i++) {
        printf("%d\n", i);
    }
end:
    return;
}

int main() {
    short_func();
    long_func();
    return 0;
}
