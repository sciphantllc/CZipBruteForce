// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <conio.h>
#include <windows.h>
#include <emmintrin.h>
#include <math.h>

#define SAFE_MEM_RET(x) if (NULL==(x)){return -1;}
#define QWORD unsigned long long

#include "zlib.h"
