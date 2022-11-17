#include "config.h"

/* We only need this memmem() function if it doesn't exist in the C
   library. It exists in GNU libc and on MacOS, but apparently not on
   Windows. */

#ifndef HAVE_MEMMEM


#include <string.h>		/* We use memcmp() */
#include <assert.h>
#include "export.h"


/* memmem -- locate a byte substring in a byte string */
EXPORT void *memmem(const void *haystack, size_t haystacklen,
		    const void *needle, size_t needlelen)
{
  /* If haystack is NULL, haystacklen must be 0. Ditto for needle. */
  assert(needlelen == 0 || needle != NULL);
  assert(haystacklen == 0 || haystack != NULL);

  /* Per the manual page on MacOS, return NULL if needlelen == 0. */
  if (needlelen == 0) return NULL;

  /* Iterate over the haystack to find the first match for needle. */
  for (; haystacklen >= needlelen; haystacklen--, haystack++)
    if (memcmp(haystack, needle, needlelen) == 0) return haystack;

  /* The haystack is now too short to contain the needle. */
  return NULL;
}


#endif	/* HAVE_MEMMEM */
