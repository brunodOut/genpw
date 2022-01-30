/**
 * genpw:
 * 	A simple  customizable  password  generator written 
 * 	for learning purposes but  also for my own personal
 * 	preferences regarding the  generation of passwords.
 * 	I plan to  make  it  less  shitty  someday so other
 * 	people could use it too.
 *
 * Description: Uses a buffer  of  random size from the RNG
 * 	(/dev/random on Linux) and hashes it with a SHA-512
 * 	algorythim,  then  converts  the  512-bit hash into
 * 	either a single character or an hexadecimal form of
 * 	the character (randomized  to be around 80% hex and
 * 	20% single char). When  hex,  the  letters might be
 * 	upper or lower case, also randomly.
 *
 * Copyright(C)
 * 	Bruno Moreira-Guedes <brunodout.dev@gmail.com>
 *
 * License: 
 * 	GPL v3 - see:  <http://www.gnu.org/licenses/>
 *
 * */


#include <stdio.h>
#include <stdlib.h>
#include <nettle/sha2.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <getopt.h>

#define RANGE_START 0x20
#define RANGE_STOP 0x7E
#define RANGE_SIZE (RANGE_STOP - RANGE_START + 1)
#define RANGE_CHAR(n) ((n % RANGE_SIZE) + RANGE_START)
#define NC 0

#ifdef __DEBUG__
#define d_msg_f(msg, ...) fprintf(stderr, \
				"DEBUG: " msg "\n", \
			       	__VA_ARGS__)
#define d_msg(msg) fprintf(stderr, "DEBUG" msg "\n")
#define d_opt_status(opt, stt) d_msg(opt " is " stt)
#else
#define d_msg_f(msg, ...)
#define d_msg(msg)
#define d_opt_status(opt, stt)
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
			  0x3D, 0x3E, NC };
const char special_chr[] = { 0x5E, 0x7E, NC };

struct genpwd_options {
	int space;
	int punct;
	int quote;
	int common;
	int bracket;
	int comput;
	int slash;
	int math;
	int special;
	size_t size;
	unsigned int max_read_trials;
	size_t c_gen;
};

struct genpwd_options g_opt = {
	.space = 0, .punct = 0, .quote = 0,
	.common = 1, .bracket = 0, .c_gen = 0, 
	.comput = 0, .slash = 0, .math = 0,
	.special = 0, .size = 16, .max_read_trials = 5
};



static inline void err_msg(char *err_m, int exstt)
{

	fprintf(stderr, "%s\n",  err_m);
	perror("Probably related to this error");
	exit(exstt);
}

static inline char * pick_case(uint8_t num, char *s)
{
       register char chr = (num % 2 == 0) ? 'x' : 'X';
       register char *p = s;

       while (*p++ != 0) 
	       *p = (*p == 'x' || *p == 'X') ? chr : *p;

       return s;
}

void parse_options(int argc, char **argv){
	int idx = 0;
	int c;
	char *shopts = "spqNbcamlz:t:h";
	struct option lopts[] = {
		{"space-char", no_argument, &g_opt.space,
			1},
		{"punctuation-chars", no_argument,
			&g_opt.punct, 1},
		{"quotation-chars", no_argument, 
			&g_opt.quote, 1},
		{"no-common-symbols", no_argument, 
			&g_opt.common, 0},
		{"brackets", no_argument, &g_opt.bracket, 
			1},
		{"computational-symbols", no_argument,
			&g_opt.comput, 1},
		{"slashes", no_argument, &g_opt.slash, 1},
		{"math-operators", no_argument, 
			&g_opt.math, 1},
		{"special", no_argument, &g_opt.special, 
			1},
		{"password-size", required_argument, NULL,
			'z'},
		{"read-retries", required_argument, NULL,
			't'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	}; 
	while ((c = getopt_long(argc, argv, shopts, 
				lopts, &idx) != -1))
	{
		switch(c){
			case 0:
				d_msg_f("The %s option is off",
				      lopts[idx].name);
				break;
			case 1:
				d_msg_f("The %s option is on",
				      lopts[idx].name);
				break;
			case 's':
				d_opt_status("status", "on");
				g_opt.space = 1;
				break;
			case 'p':
				d_opt_status("punctuation", "on");
				g_opt.punct = 1;
				break;
			case 'q':
				d_opt_status("quotation", "on");
				g_opt.quote = 1;
				break;
			case 'N':
				d_opt_status("common symbols", "off");
				g_opt.common = 0;
				break;
			case 'b':
				d_opt_status("brakets", "on");
				g_opt.bracket = 1;
				break;
			case 'c':
				d_opt_status("computational symbols", "on");
				g_opt.comput = 1;
				break;
			case 'a':
				d_opt_status("slashes", "on");
				g_opt.slash = 1;
				break;
			case 'm':
				d_opt_status("math operators", "on");
				g_opt.math = 0;
				break;
			case 'l':
				d_opt_status("slashes", "on");
				g_opt.special = 1;
				break;
			case 'z':
				g_opt.size = atoi(optarg);
				d_msg_f("Password size set to %zu", g_opt.size);
				if (!g_opt.size)
				    err_msg("Password size must be greater than zero", errno);
				break;
			case 't':
				g_opt.max_read_trials = atoi(optarg);
				d_msg_f("Number of trials set to %zu", g_opt.size);
				if (!g_opt.max_read_trials)
				    err_msg("Retries must be greater than zero", errno);
				break;
			case 'h':
				printf("Help:\n");
			default:
				err_msg("Invalid Command-line Argument", -1);
		}
	}	
}

bool isallowed(char chr) 
{
	bool ret = false;
	
	// if some allowed option matches the character,
	//    we flag it as temporarily true
	if ((g_opt.space && strchr(space_chr, chr)) ||
	     (g_opt.punct && strchr(punct_chr, chr)) ||
	     (g_opt.quote && strchr(quote_chr, chr)) ||
	     (g_opt.common && strchr(common_chr, chr)) ||
	     (g_opt.bracket && strchr(bracket_chr, chr)) ||
	     (g_opt.comput && 
	      strchr(computing_meaningful_chr, chr)) ||
	     (g_opt.slash && strchr(slash_chr, chr)) ||
	     (g_opt.math && strchr(math_chr, chr)) ||
	     (g_opt.special && strchr(special_chr, chr)))
	{
		ret = true;
	}

	if (!ret) return ret;
	
	if ((!g_opt.space && strchr(space_chr, chr)) ||
	     (!g_opt.punct && strchr(punct_chr, chr)) ||
	     (!g_opt.quote && strchr(quote_chr, chr)) ||
	     (!g_opt.common && strchr(common_chr, chr)) ||
	     (!g_opt.bracket &&
	      strchr(bracket_chr, chr)) ||
	     (!g_opt.comput && 
	      strchr(computing_meaningful_chr, chr)) ||
	     (!g_opt.slash && strchr(slash_chr, chr)) ||
	     (!g_opt.math && strchr(math_chr, chr)) ||
	     (!g_opt.special && strchr(special_chr, chr)))
	{
		ret = false;
	}

	return ret;

}

size_t read_uint8_t_bytes(void *ptr, FILE *stream, 
			  size_t times, char *errmsg)
{
	unsigned int trials = 0;
	void *p = ptr;
	size_t ret = 0;
	
	if (p == NULL) // null pointer passed
		return ret;

	do
	{
		ret += fread(p, sizeof(uint8_t), 
				   times, stream);
		p += ret;
		if (++trials == g_opt.max_read_trials)
		       break;	
	}
	while ( ret < (times * sizeof(uint8_t)) && 
		(p - ptr) < times );
	
	if (ret < (times * sizeof(uint8_t))) 
		err_msg(errmsg, errno);

	return ret;
}

size_t read_uint8_t(void *ptr, FILE *stream, char *errmsg)
{
	return read_uint8_t_bytes(ptr, stream, 1, errmsg);
}

char process_chr(uint8_t chr)
{
	int i_chr = RANGE_CHAR(chr);
	int iter = 0;
	while (!isalnum(i_chr) && !isallowed(chr)) {
		i_chr = RANGE_CHAR(++iter * i_chr);
	}
	return (char) i_chr;
}

void process_digest(uint8_t *digest) 
{
	char output[SHA512_DIGEST_SIZE+1];
	register char *out_ptr = output;
	const char *out_end =
		   output + SHA512_DIGEST_SIZE + 1;
	register uint8_t *dg_ptr = digest;
	const uint8_t *dg_end = digest + SHA512_DIGEST_SIZE;

	char *fmt[] = { "%02x", "%02X" };

	bzero(output, sizeof(output));

	if (digest == NULL){
		err_msg("Invalid digest pointer", errno);
		return;
	}

	while ( dg_ptr < dg_end && out_ptr < out_end && 
		out_ptr - output < g_opt.size)
	{
		if (*dg_ptr % 5 == 0) {
			*(out_ptr++) = 
				process_chr(*dg_ptr++);
			if ( out_ptr - output == 
			     g_opt.size )
			       break;	
			*(out_ptr++) = 
				process_chr(*dg_ptr++);
			continue;
		}

		sprintf(out_ptr, fmt[*dg_ptr % 2], 
			*dg_ptr);
		dg_ptr++;
		while (out_ptr < out_end && *out_ptr != 0 
		       && out_ptr - output < g_opt.size)
		{
			out_ptr++;
		}
	}

	printf("%.*s", (int) g_opt.size, output);

}

int main(int argc, char **argv)
{
	FILE *rdgen = fopen("/dev/random", "r");
	uint8_t byte;
	size_t buf_size;
	uint8_t *buffer = NULL;
	struct sha512_ctx ctx;
	uint8_t digest[SHA512_DIGEST_SIZE];

	parse_options(argc, argv);

	read_uint8_t(&byte, rdgen, 
			"Error reading initial byte");
	buf_size = byte;

	read_uint8_t(&byte, rdgen, 
			"Error reading initial byte");

	buf_size *= byte;
	buffer = malloc(buf_size);

	if (buffer == NULL) {
		perror("Memory error");
		return errno;
	}

	read_uint8_t_bytes(buffer, rdgen, buf_size,
			   "Error generating random data");

	sha512_init(&ctx);
	sha512_update(&ctx, buf_size, buffer);

	free(buffer);

	sha512_digest(&ctx, SHA512_DIGEST_SIZE, digest);
	process_digest(digest);
	
	printf("\n");
}

