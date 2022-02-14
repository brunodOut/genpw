/* -*- c-basic-offset: 8 -*-
        
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <nettle/sha2.h>

#define RANGE_START 0x20
#define RANGE_STOP 0x7E
#define RANGE_SIZE (RANGE_STOP - RANGE_START + 1)
#define RANGE_CHAR(n) ((n % RANGE_SIZE) + RANGE_START)
#define NC 0

#ifdef __DEBUG__
#define d_msg_f(msg, ...) fprintf(stderr, \
				"DEBUG: " msg "\n", \
			       	__VA_ARGS__)
#define d_msg(msg) fprintf(stderr, "DEBUG: " msg "\n")
#define d_opt_status(opt, stt) d_msg(opt " is " stt)
#define d_opt_status_val(opt, stt, fmt) d_msg_f(opt " is set to " fmt, stt)
#define d_opt_status_size(opt, stt) d_opt_status_val(opt, stt, "%zu")
#define d_opt_status_int(opt, stt) d_opt_status_val(opt, stt, "%d")
#define d_opt_status_uint(opt, stt) d_opt_status_val(opt, stt, "%u")
#define d_opt_status_s_s(opt, stt) d_msg_f("%s is set to %s", opt, stt)
#define d_opt_status_s_size(opt, stt) d_msg_f("%s is set to %zu", opt, stt)
#define d_opt_status_s_int(opt, stt) d_msg_f("%s is set to %d", opt, stt)
#else
#define d_msg_f(msg, ...)
#define d_msg(msg)
#define d_opt_status(opt, stt)
#define d_opt_status_val(opt, stt, fmt)
#define d_opt_status_size(opt, stt)
#define d_opt_status_int(opt, stt)
#define d_opt_status_uint(opt, stt)
#define d_opt_status_s_s(opt_s, opt)
#define d_opt_status_s_size(opt_s, opt)
#define d_opt_status_s_int(opt, stt)
#endif


/* Character Classes
 * 
 * Those  classes  are  based  on my  own  experience  with
 * accepted characters in a  wide range of environments and
 * should  be  improved  based  on  research  of  websites, 
 * systems and common libraries that do password validation
 * */
const char space_chr[] = { 0x20, NC };
const char punct_chr[] = { 0x21, 0x2C, 0x2E, 0x2E, 
			   0x3A, 0x3B, 0x3F, NC };
const char quote_chr[] = { 0x22, 0x27, 0x60, NC };
const char common_chr[] = { 0x23, 0x24, 0x25, 
			    0x2A, 0x40, 0x5F, NC };
const char bracket_chr[] = { 0x28, 0x29, 0x5B, 0x5D, 
			     0x7B, 0x7D, NC };
const char computing_meaningful_chr[] = { 0x22, 0x25, 0x26,
					  0x27, 0x2A, 0x2F, 
					  0x3F, 0x7C, NC };
const char slash_chr[] = { 0x2F, 0x5C, NC };
const char math_chr[] = { 0x2B, 0x2D, 0x3C,
			  0x3D, 0x3E, 0x42, 0x47, NC };
const char special_chr[] = { 0x5E, 0x7E, NC };

typedef enum {
	O_BRACKET = 'b',
	O_COMPUTATIONAL = 'c',
	O_HELP = 'h',
	O_MATH = 'm',
	O_COMMON_SYMBOLS = 'n',
	O_NO_COMMON_SYMBOLS = 'N',
	O_OPTIONS = 'o',
	O_PASS_SIZE = 'p',
	O_PUNCTUATION = 'u',
	O_QUOTATION = 'q',
	O_RANDNUMGEN = 'g',
	O_READ_RETRIES = 'r',
	O_SLASHES = 'l',
	O_SPACE = 's',
	O_SPECIAL = 'e',
	O_MAX_OPT = 122
} e_opts;

char * opts_s[] = {
	[O_BRACKET] = "brackets",
	[O_COMPUTATIONAL] = "computational-symbols",
	[O_HELP] = "help", [O_MATH] = "math",
	[O_COMMON_SYMBOLS] = "common-symbols",
	[O_NO_COMMON_SYMBOLS] = "no-common-symbols",
	[O_OPTIONS] = "options",
	[O_PASS_SIZE] = "password-size",
	[O_PUNCTUATION] = "punctuation",
	[O_QUOTATION] = "quotation",
	[O_READ_RETRIES] = "read-retries", 
	[O_RANDNUMGEN] = "random-number-generator",
	[O_SLASHES] = "slashes",
	[O_SPACE] = "space", [O_SPECIAL] = "special"
};
struct genpwd_options {
	int bracket;
	int comput;
	int common;
	int math;
	size_t pwd_size; //password size
	int punct;
	int quote;
	char rand_gen [PATH_MAX + 1];
	unsigned int read_retries;
	int slash;
	int space;
	int special;
	size_t c_gen; //future count for currently generated chars
};

struct genpwd_options g_opt = {
	.bracket = 0, .comput = 0, .common = 1, .math = 0,
	.pwd_size = 16, .punct = 0, .quote = 0,
	.rand_gen = "/dev/random", .read_retries = 5, 
	.slash = 0, .space = 0, .special = 0, .c_gen = 0
};

void *opts_p[] = {
	[O_BRACKET] = &g_opt.bracket,
	[O_COMPUTATIONAL] = &g_opt.comput,
	[O_COMMON_SYMBOLS] = &g_opt.common,
	[O_NO_COMMON_SYMBOLS] = &g_opt.common,
	[O_MATH] = &g_opt.math, 
	[O_PASS_SIZE] = &g_opt.pwd_size,
	[O_PUNCTUATION] = &g_opt.punct, 
	[O_QUOTATION] = &g_opt.quote, 
	[O_READ_RETRIES] = &g_opt.read_retries, 
	[O_RANDNUMGEN] = &g_opt.rand_gen,
	[O_SLASHES] = &g_opt.slash, [O_SPACE] = &g_opt.space,
	[O_SPECIAL] = &g_opt.special
};