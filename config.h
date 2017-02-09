#ifndef CONFIG_H_
#define CONFIG_H_

#if defined(_WIN32)
#include "config.win.h"
#elif defined(__APPLE__)
#include "config.macos.h"
#elif defined(__linux__)
#include "config.linux.h"
#endif

#endif // CONFIG_H_