#include "Log.h"

static bool enableSubmodule = false;

void setSubmodule() {
    enableSubmodule = true;
}

void printFilename(std::string filename) {
    std::string basenameStr(filename.substr(filename.rfind("/") + 1));
    unsigned long hash = 5381;
    for (char const &c : basenameStr)
    {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    printf("\e[0;%dm", allColors[hash % NColors]);

    printf("%s", basenameStr.c_str());
    printf(colorReset);
}

void debug(std::string filename, int line, std::string submodule, const char *format, ...) {
    printf(colorRed);
    printf("D ");
    if (enableSubmodule) {
        printf(colorReset);
        printf("[%s] ", submodule.c_str());
    }
    printFilename(filename);
    printf(":%d: ", line);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
};

void error(std::string filename, int line, std::string submodule, const char *format, ...) {
    printf(colorRed);
    printf("E ");
    if (enableSubmodule) {
        printf(colorReset);
        printf("[%s] ", submodule.c_str());
    }
    printFilename(filename);
    printf(":%d: ", line);
    printf(colorRed);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
};

void info(std::string filename, int line, std::string submodule, const char *format, ...) {
    printf(colorBlue);
    printf("I ");
    if (enableSubmodule) {
        printf(colorReset);
        printf("[%s] ", submodule.c_str());
    }
    printFilename(filename);
    printf(":%d: ", line);
    printf(colorReset);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
};
