/*
 * export.h -- header file for programs that use cexport
 *
 * Copyright © 1994-2000 World Wide Web Consortium
 * See http://www.w3.org/Consortium/Legal/copyright-software
 *
 *
 * Functions, type definitions, variable declarations can all be
 * exported by putting EXPORT (uppercase only) in front of the
 * declaration. The declarations must be ANSI-C. Macros can be
 * exported with EXPORTDEF. Examples:
 *
 * EXPORT int sqr(int n) {...}		-- exports function sqr()
 * EXPORT typedef struct _Str * MyStr;	-- exports type MyStr
 * EXPORT int maximum;			-- exports variable maximum
 * #define max(a,b) ((a)>(b)?(a):(b))
 * EXPORTDEF(max(a,b))			-- exports macro max(a,b)
 */
#ifndef _EXPORT_H_
#define _EXPORT_H_

#ifndef __export
#define EXPORT /* nothing */
#define EXPORTDEF(x) /* nothing */
#else
//#define EXPORTDEF(x) EXPORTDEF_##x x
#define EXPORTDEF(x) EXPORTDEF #x x
#endif

#endif /* _EXPORT_H_ */
