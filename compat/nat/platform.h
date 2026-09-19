#pragma once
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
/* IPv4 literal interface selection is used, never desktop interface names. */
static inline unsigned int if_nametoindex(const char *name) { (void)name; return 0; }
static inline char *if_indextoname(unsigned int index, char *name) { (void)index; (void)name; return NULL; }
void *ztnx_nat_malloc(size_t size);
void *ztnx_nat_realloc(void *ptr, size_t size);
void *ztnx_nat_calloc(size_t count, size_t size);
void ztnx_nat_free(void *ptr);
char *ztnx_nat_strdup(const char *str);
#define malloc ztnx_nat_malloc
#define realloc ztnx_nat_realloc
#define calloc ztnx_nat_calloc
#define free ztnx_nat_free
#define strdup ztnx_nat_strdup
