/* cexport.c -- create header file of EXPORT'ed declarations from c files */

/*
 * Author: Bert Bos <bert@w3.org>
 * Created: before 1995
 *
 * C files are scanned for the keyword EXPORT. Any declaration that
 * follows it is copied to a file with the extension .e. It works for
 * typedefs, #defines, variables and functions, but only if ANSI
 * prototypes are used. Macros are exported with EXPORTDEF(.)
 *
 * Examples:
 *
 * EXPORT typedef int * IntPtr		-- export IntPtr
 *
 * EXPORT void walkTree(Tree t)		-- export walkTree()
 *
 * #define max(a,b) ((a)>(b)?(a):(b))
 * EXPORTDEF(max(a,b))			-- export max(a,b)
 *
 * Files are first piped through the C preprocessor cpp.
 *
 * Command line options:
 * -c <cppcmd>: use <cppcmd> instead of cpp
 * -e <extension>: use <extension> instead of '.e'
 * other options are passed to cpp
 *
 * The program is not very smart about C syntax, but it doesn't have
 * to be, as long as the input is correct ANSI C. If it is not, no
 * warnings will be given (except possibly for unmatched braces,
 * quotes and paretheses), but the output will not be correct C,
 * either.
 *
 * TO DO: an option to check if the new .e file is different any
 * existing one and to keep the old one in that case. (Useful to save
 * unnecessary recompilations.)
 */

#include "config.h"
#include <stdio.h>
#if STDC_HEADERS
# include <string.h>
#else
# ifndef HAVE_STRCHR
#  define strchr index
#  define strrchr rindex
# endif
#endif
#include <ctype.h>
#include <stdlib.h>

#ifndef CPP
#define CPP "cc -E"
#endif

#define LINELEN BUFSIZ

static int err = 0;                         /* Global error counter */
static char *cppcmd = CPP;
static char *extension = ".e";

static FILE *in, *out;
static int eof;
static long lineno;
static char line[LINELEN];
static char *curname;

/***************************************************************************
 * get_line -- read next line, return 0 if eof
 ***************************************************************************/
static int get_line()
{
    static char buf[BUFSIZ];
    char *s;
    int i;

    do {
	if (eof)
	    return 0;
	else if (! fgets(line, LINELEN, in)) {
	    eof = 1;
	    return 0;
	} else if (line[0] != '#') {
	    lineno++;
	    return 1;
	} else if (line[1] == ' ') {
	    i = 2; while (isspace(line[i])) i++;
	    if (! isdigit(line[i])) {
		lineno++;
		return 1;
	    } else {
		lineno = strtol(line + i, &s, 0) - 1;
		if (*(s+1) != '"') {
		  strcpy(buf, s + 1);
		  buf[strlen(buf)-1] = '\0';
		} else {
		  strcpy(buf, s + 2);
		  for (i = 2; buf[i] != '"'; i++) ;
		  buf[i] = '\0';
		}
		if (buf[0]) curname = buf;
	    }
	} else if (line[1] == 'l' && strncmp(line, "#line", 5) == 0) {
	    lineno = strtol(line + 5, &s, 0) - 1;
	    if (*(s+1) != '"') {
	      strcpy(buf, s + 1);
	      buf[strlen(buf)-1] = '\0';
	    } else {
	      strcpy(buf, s + 2);
	      for (i = 2; buf[i] != '"'; i++) ;
	      buf[i] = '\0';
	    }
	    if (buf[0]) curname = buf;
	} else {
	    lineno++;
	    return 1;
	}
    } while (1);
}

/***************************************************************************
 * exportdef -- copy a #define to output
 ***************************************************************************/
static void exportdef(i)
    long i;
{
    unsigned long len;

    /*
     * TO DO: encountering an end of file should produce a suitable error
     * message: end of file in middle of macro definition.
     */
    
    fputs("#define ", out);			/* EXPORTDEF -> #define */

    /* Unquote the following string */
    for (i += 10; line[i] && line[i] != '"'; i++) ;
    for (i++; line[i] && line[i] != '"'; i++) putc(line[i], out);
    putc(' ', out);

    fputs(line + i + 1, out);			/* Write rest of line */
    len = strlen(line);				/* Continuation lines? */
    while (len >= 2 && line[len-2] == '\\') {
        if (! get_line()) break;
        fputs(line, out);
        len = strlen(line);
    }
}
    
/***************************************************************************
 * export -- copy next declaration to output
 ***************************************************************************/
static void export(i)
    long *i;
{
    int brace, paren, squote, dquote, comment, stop, is_typedef, start, is_enum,
      is_extern, is_struct;

    /*
     * TO DO: End of file while any of the variables is still
     * non-null is also an error.
     */
     
    *i += 6;                                /* Skip "EXPORT" */
    comment = 0;
    squote = 0;
    dquote = 0;
    paren = 0;
    brace = 0;
    stop = 0;
    is_typedef = 0;
    is_enum = 0;
    is_extern = 0;
    is_struct = 0;
    start = 1;
    do {
        switch (line[*i]) {
	case '\\':
	    if (line[*i+1]) (*i)++;		/* Skip next char */
	    break;
        case '{':
            if (!comment && !squote && !dquote && !paren) brace++;
            break;
        case '}':
            if (!comment && !squote && !dquote && !paren) brace--;
	    if (brace < 0) {
		fprintf(stderr, "%s:%ld: syntax error (too many '}'s)\n",
			curname, lineno);
		err++;
		brace = 0;
	    }
            break;
        case '"':
            if (!comment && !squote) dquote = !dquote;
            break;
        case '\'':
            if (!comment && !dquote) squote = !squote;
            break;
        case '*':
            if (!comment && !dquote && !squote && *i > 0 && line[*i-1] == '/')
                comment = 1;                /* Start of comment */
            break;
        case '/':                           /* Possible end of comment */
            if (comment && *i > 0 && line[*i-1] == '*') comment = 0;
            break;
        case '(':
            if (!comment && !dquote && !squote && !brace) paren++;
            break;
        case ')':
            if (!comment && !dquote && !squote && !brace) {
	        paren--;
		if (paren == 0 && !is_typedef) {
		    putc(')', out);
		    putc(';', out);
		    putc('\n', out);
		    stop = 1;
		}
	    }
            break;
        case ';':
            if (!comment && !dquote && !squote && !paren && !brace) {
                putc(';', out);
                putc('\n', out);
                stop = 1;
            }
            break;
        case '=':
            if (!comment && !dquote && !squote && !brace && !paren) {
                putc(';', out);             /* End of variable decl. */
		putc('\n', out);
                stop = 1;
            }
            break;
	case '\n':
	    if (dquote) {
		fprintf(stderr,
			"%s:%ld: syntax error (string didn't end)\n",
			curname, lineno);
		err++;
		dquote = 0;
	    }
	    if (squote) {
		fprintf(stderr,
			"%s:%ld: syntax error (char const didn't end)\n",
			curname, lineno);
		err++;
		squote = 0;
	    }
	    break;
        case '\0':
            if (! get_line()) stop = 1;
            else *i = -1;
            break;
	case 't':
	    if (!comment && !squote && !dquote && paren == 0 && brace == 0
		&& strncmp("typedef", &line[*i], 7) == 0)
		is_typedef = 1;
	    break;
	case 's':
	    if (!comment && !squote && !dquote && paren == 0 && brace == 0
		&& strncmp("struct", &line[*i], 6) == 0)
		is_struct = 1;
	    break;
	case 'e':
	    if (!comment && !squote && !dquote && paren == 0 && brace == 0) {
	        if (strncmp("enum", &line[*i], 4) == 0) is_enum = 1;
		else if (strncmp("extern", &line[*i], 6) == 0) is_extern = 1;
	    }
	    break;
        }
	if (! stop) {
	  if (*i >= 0) {
	    if (! start) {
	      putc(line[*i], out);
	    } else if (! isspace(line[*i])) {
	      if (! is_typedef && ! is_enum && ! is_extern && ! is_struct)
		fputs("extern ", out);
	      putc(line[*i], out);
	      start = 0;
	    }
	  }
	  (*i)++;
	}
    } while (! stop);
}
    

/***************************************************************************
 * process -- scan file and write exported declarations
 ***************************************************************************/
static void process(file, cpp)
    char *file, *cpp;
{
    char cmd[1024], *s, outname[1024];
    int brace, paren, dquote, squote, comment;
    long i;

    strcpy(cmd, cppcmd);			/* Build cpp command line */
    strcat(cmd, cpp);
    strcat(cmd, file ? file : "-");
    eof = 0;
    lineno = 0;
    in = popen(cmd, "r");			/* Pipe file through cpp */
    if (! in) { perror(cmd); err++; return; }
    
    if (file) {
        strcpy(outname, file);			/* Construct output file */
        s = strrchr(outname, '.');		/* Extension becomes .e */
        if (! s) s = outname + strlen(outname);
        strcpy(s, extension);
        out = fopen(outname, "w");
        if (! out) { perror(outname); err++; return; }
    } else {
        out = stdout;				/* No file name, use stdout */
    }
    if (file) curname = file; else curname = "<stdin>";

    /*
     * If the word EXPORT is found and it is not inside a comment, between
     * quotes, parentheses or braces, the export() function is called to copy
     * the declaration to the out file. When the export() function ends, `line'
     * may have changed, but `i' points to the last copied character.
     *
     * If the word EXPORTDEF is found at the start of a line and it
     * is not inside a comment or between quotes, exportdef is called.
     */
    comment = 0;
    dquote = 0;
    squote = 0;
    paren = 0;
    brace = 0;
    while (get_line()) {
        for (i = 0; line[i]; i++) {
            switch (line[i]) {
	    case '\\':
		if (line[i+1]) i++;		/* Skip next char */
		break;
            case '{':
                if (!comment && !dquote && !squote) brace++;
                break;
            case '}':
                if (!comment && !dquote && !squote) brace--;
		if (brace < 0) {
		    fprintf(stderr, "%s:%ld: syntax error (too many '}'s)\n",
			    curname, lineno);
		    err++;
		    brace = 0;
		}
                break;
            case '(':
                if (!comment && !dquote && !squote) paren++;
                break;
            case ')':
                if (!comment && !dquote && !squote) paren--;
		if (paren < 0) {
		    fprintf(stderr, "%s:%ld: syntax error (too many ')'s)\n",
			    curname, lineno);
		    err++;
		    paren = 0;
		}
                break;
            case '\'':
                if (!comment && !dquote) squote = !squote;
                break;
            case '"':
                if (!comment && !squote) dquote = !dquote;
                break;
	    case '\n':
		if (dquote) {
		    fprintf(stderr,
			    "%s:%ld: syntax error (string didn't end)\n",
			    curname, lineno);
		    err++;
		    dquote = 0;
		}
		if (squote) {
		    fprintf(stderr,
			    "%s:%ld: syntax error (char const didn't end)\n",
			    curname, lineno);
		    err++;
		    squote = 0;
		}
		break;
            case '*':
                if (!comment && !dquote && !squote && i > 0 && line[i-1] == '/')
                    comment = 1;            /* Start of comment */
                break;
            case '/':                       /* Possible end of comment */
                if (comment && i > 0 && line[i-1] == '*') comment = 0;
                break;
            case 'E':
                if (comment || dquote || squote || paren != 0 || brace != 0)
                    ;
                else if (strncmp(&line[i], "EXPORT", 6) == 0
                    && (i == 0 || !isalnum(line[i-1]))
                    && !isalnum(line[i+6]))
                    export(&i);
                else if (strncmp(&line[i], "EXPORTDEF ", 10) == 0
                    && (i == 0 || !isalnum(line[i-1]))) {
                    exportdef(i);
                    i = (long) strlen(line) - 1;
                }
                break;
            }
        }
    }
    if (comment) {
	fprintf(stderr, "%s:%ld: syntax error (comment didn't end)\n",
		curname, lineno);
	err++;
    }
    if (dquote) {
	fprintf(stderr, "%s:%ld: syntax error (string didn't end)\n",
		curname, lineno);
	err++;
    }
    if (squote) {
	fprintf(stderr, "%s:%ld: syntax error (char const didn't end)\n",
		curname, lineno);
	err++;
    }
    if (file) fclose(out);
    fclose(in);
}

static void usage(s)
    char *s;
{
    fprintf(stderr,
	    "Usage: %s {-Idir|-Dsym} [-h] [-c cppcmd] [-e ext] {file}\n",
	    s);
    err++;
}

int main(argc, argv)
    int argc;
    char *argv[];
{
    char cpp[BUFSIZ];				/* Max. cmd. line length */
    int nfiles, i;

    strcpy(cpp, " -D__export ");
    nfiles = 0;
    
    for (i = 1; i < argc; i++) {
	if (!strncmp(argv[i], "-c", 2)) {	/* Replace cpp command */
            if (argv[i][2])
                cppcmd = argv[i] + 2;
            else
                cppcmd = argv[++i];
        } else if (!strncmp(argv[i], "-e", 2)) { /* Extension instead of .e */
            if (argv[i][2])
                extension = argv[i] + 2;
            else
                extension = argv[++i];
        } else if (!strncmp(argv[i], "-h", 2)) { /* -h: help */
            usage(argv[0]);
	} else if (argv[i][0] == '-' || argv[i][0] == '+') {
            strcat(cpp, argv[i]);		/* Pass options to cpp */
            strcat(cpp, " ");
        } else {				/* Not option, must be file */
            nfiles++;
            process(argv[i], cpp);
        }
    }
    if (nfiles == 0)				/* no arguments, use stdin */
        process(NULL, cpp);

    return err;
}

