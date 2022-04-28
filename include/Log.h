#ifndef __LOG_H__
#define __LOG_H__

#include <string>
#include <stdarg.h>

static constexpr const char *colorReset = "\e[0m";
static constexpr const char *colorRed = "\e[0;31m";
static constexpr const char *colorBlue = "\e[0;34m";
static constexpr const int NColors = 15;
static constexpr int allColors[NColors] = {30, 32, 33, 34, 35, 36, 37, 91, 92, 93, 94, 95, 96, 97, 98};

void debug(std::string filename, int line, std::string submodule, const char *format, ...);
void error(std::string filename, int line, std::string submodule, const char *format, ...);
void info(std::string filename, int line, std::string submodule, const char *format, ...);
void setSubmodule();

#define LOG(type, ...)                                      \
    do                                                      \
    {                                                       \
        type(__FILE__, __LINE__, "szpoter", __VA_ARGS__);   \
    } while (0)

#endif  // __LOG_H__
