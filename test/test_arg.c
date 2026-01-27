#include <stdio.h>
#include <stdlib.h>

extern char **environ;

int main(int argc, char* argv[] ) {
    for(int i = 0; i < argc; i++) {
        printf("%d: %s\n", i, argv[i]);
    }
    for(char** env = environ; *env != NULL; env++) {
        printf("env: %s\n", *env);
    }
    return 0x22;
}
