/* -*- c-basic-offset: 8 -*-
 *
 * genpw:
 * 	    A simple  customizable  password  generator written 
 * 	    for learning purposes but  also for my own personal
 * 	    preferences regarding the  generation of passwords.
 * 	    I plan to  make  it  less  shitty  someday so other
 * 	    people could use it too.
 *
 * Description: Uses a buffer  of  random size from the RNG
 * 	    (/dev/random on Linux) and hashes it with a SHA-512
 * 	    algorythim,  then  converts  the  512-bit hash into
 * 	    either a single character or an hexadecimal form of
 * 	    the character (randomized  to be around 80% hex and
 * 	    20% single char). When  hex,  the  letters might be
 * 	    upper or lower case, also randomly.
 * 
 * Main file and routines
 * 
 * Copyright(C) Bruno Moreira-Guedes <code@brunodOut.dev>
 *
 * License: 
 * 	GPL v3 - see:  <http://www.gnu.org/licenses/>
 *
 *
 */

#define __GENPWD_C
#include "genpwd.h"

static inline void setopt(e_opts opt, void *val)
{
	if (opt == O_OPTIONS || opt == O_HELP) {
		// no execution options, nothing to do
		d_msg("UNEXPECTED BEHAVIOR: " 
			  "setopt received O_OPTIONS or O_HELP");
		return;
	}
	else if (opt == O_PASS_SIZE) {
		size_t *o = opts_p[opt];
		size_t v = atoi((char *) val);
		assert(v > 0);
		d_opt_status_s_size(opts_s[opt], v);
		*o = v;
		return;
	} else if (opt == O_RANDNUMGEN) {
		char *o = opts_p[opt];
		char *v = val;
		strncpy(o, v, PATH_MAX);
		//sets \0 character in case the str is truncated:
		o[PATH_MAX] = 0; 
	} else if (opt == O_READ_RETRIES) {
		unsigned int *o = opts_p[opt];
		unsigned int v = atoi((char *) val);
		assert(v > 0);
		*o = v;
		return;
	}
	else { // all other options have same treatment
		int *v = val;
		int *o = opts_p[opt];
		assert(v != NULL && o != NULL);
		*o = *v;
	}
}

static inline void err_msg(char *err_m, int exstt)
{

	fprintf(stderr, "%s\n",  err_m);
	perror("Probably related to this error");
	exit(exstt);
}

static inline char *pick_case(uint8_t num, char *s)
{
       register char chr = (num % 2 == 0) ? 'x' : 'X';
       register char *p = s;

       while (*p++ != 0) 
	       *p = (*p == 'x' || *p == 'X') ? chr : *p;

       return s;
}

void parse_options(int argc, char **argv){
	int idx = 0;
	int c = -2;
	char *shopts = "bchmNo:p:uqr:lg:se";

	struct option lopts[] = {
		{opts_s[O_BRACKET], no_argument, 
			opts_p[O_BRACKET], 1},
		{opts_s[O_COMPUTATIONAL], no_argument, 
			opts_p[O_COMPUTATIONAL], 1},
		{opts_s[O_HELP], no_argument, NULL, 0},
		{opts_s[O_MATH], no_argument, opts_p[O_MATH], 1},
		{opts_s[O_NO_COMMON_SYMBOLS], no_argument, 
			opts_p[O_NO_COMMON_SYMBOLS], 0},
		{opts_s[O_OPTIONS], required_argument, NULL, 
			O_OPTIONS},
		{opts_s[O_PASS_SIZE], required_argument, NULL, 
			O_PASS_SIZE},
		{opts_s[O_PUNCTUATION], no_argument, 
			opts_p[O_PUNCTUATION], 1},
		{opts_s[O_QUOTATION], no_argument, 
			opts_p[O_QUOTATION], 1},
		{opts_s[O_RANDNUMGEN], required_argument, NULL,
			O_RANDNUMGEN},
		{opts_s[O_READ_RETRIES], required_argument, NULL,
			O_READ_RETRIES},
		{opts_s[O_SLASHES], no_argument, opts_p[O_SLASHES], 
			1},
		{opts_s[O_SPACE], no_argument, opts_p[O_SPACE], 1},
		{opts_s[O_SPECIAL], no_argument, opts_p[O_SPECIAL], 
			1},
		/*{"space-char", no_argument, &g_opt.space,
			's'},
		{"punctuation-chars", no_argument,
			&g_opt.punct, 'p'},
		{"quotation-chars", no_argument, 
			&g_opt.quote, 'q'},
		{"no-common-symbols", no_argument, 
			&g_opt.common, 0},
		{"brackets", no_argument, &g_opt.bracket, 
			'b'},
		{"computational-symbols", no_argument,
			&g_opt.comput, 'c'},
		{"slashes", no_argument, &g_opt.slash, 'h'},
		{"math-operators", no_argument, 
			&g_opt.math, 'm'},
		{"special", no_argument, &g_opt.special, 
			'l'},
		{"password-size", required_argument, NULL,
			'z'},
		{"read-retries", required_argument, NULL,
			't'},
		{"help", no_argument, NULL, 'h'},*/
		{NULL, 0, NULL, 0}
	}; 
	while ((c = getopt_long(argc, argv, shopts, 
				lopts, &idx)) != -1)
	{
		if (c == O_HELP) {
			err_msg("User asked for help", -1);
			return;
		} else if (c == 1 || c == 0) {
			// man pages say it's not supposed to return 1
			d_msg_f("The %s option is set to %s (c=%d)", 
					lopts[idx].name, //fix it
					c == 1 ? "on" : "off", c);
					continue;
		} else if ( c == O_PASS_SIZE || 
					c == O_READ_RETRIES || 
					c == O_RANDNUMGEN )
		{
			d_opt_status_s_s(opts_s[c], optarg);
			setopt(c, optarg);
			continue;
		} else if (c == O_OPTIONS) {
			// FIXME: Make it actually work
			char *subopts = optarg;
			char *val = NULL;
			int err = 0;
			
			while(subopts != NULL && *subopts != 0 && !err)
			{
				c = getsubopt(&subopts, opts_s, &val);
				if (c == -1 || c == O_OPTIONS) {
					fprintf(stderr, 
							"Invalid option ignored: %s\n",
							val);
					continue;
				}
				if (c == O_HELP) {
					//fprintf(stderr,
					err_msg("User requested help", 0);
					break;
				}
				else if ( c == O_PASS_SIZE || 
						  c == O_READ_RETRIES )
				{
					setopt(c, val);
					continue;
				} else {
					int value = 
						(c != O_NO_COMMON_SYMBOLS) ? 1 : 0;
					setopt(c, &value);
					continue;
				}
			}
			continue;
		} else if ( c >= 0 && c < sizeof(opts_s)  && 
					opts_s[c] != NULL) {
			/* if it's contained in the string arrays and
				not the ':' sign, then it's a valid option;
				So we check if it's a disabling option
				(only O_NO_COMMON_SYMBOLS so far) or an
				enabling option (all others) and pass the
				proper value to setopt()
			*/
			int val = (c == O_NO_COMMON_SYMBOLS) ? 0 : 1;
			d_opt_status_s_int(opts_s[c], val);
			setopt(c, &val);
			continue;
		} 
		else {
			err_msg("Invalid Command-line Argument", -1);
			return;
		}

		/*switch(c){
			case 0:
				d_msg_f("The %s option is off",
				      lopts[idx].name);
				break;
			case 1:
				d_msg_f("The %s option is on",
				      lopts[idx].name);
				break;
			case O_BRACKET:
				d_opt_status("brakets", "on");
				g_opt.bracket = 1;
				break;
			case O_COMMON_SYMBOLS:
				d_opt_status("common symbols", "off");
				g_opt.common = 0;
				break;
			case O_COMPUTATIONAL:
				d_opt_status("computational symbols", "on");
				g_opt.comput = 1;
				break;
			case O_MATH:
				d_opt_status("math operators", "on");
				g_opt.math = 0;
				break;
			case O_OPTIONS:
				// implement
				char *sub = optarg;
				char *val = NULL;
				int errfnd = 0;
				
				while (*subopts != 0 && !errfnd) {
					switch(getsubopt(&subopts, opts_s, &val)) {
						case O_BRACKET:
							
					}
				}
				break;
			case O_PASS_SIZE:
				g_opt.size = atoi(optarg);
				d_msg_f("Password size set to %zu", g_opt.size);
				if (!g_opt.size)
				    err_msg("Password size must be greater than zero", errno);
				break;
			case O_PUNCTUATION:
				d_opt_status("punctuation", "on");
				g_opt.punct = 1;
				break;
			case O_QUOTATION:
				d_opt_status("quotation", "on");
				g_opt.quote = 1;
				break;
			case O_READ_RETRIES:
				g_opt.max_read_trials = atoi(optarg);
				d_msg_f("Number of trials set to %zu", g_opt.size);
				if (!g_opt.max_read_trials)
				    err_msg("Retries must be greater than zero", errno);
				break;
			case O_SLASHES:
				d_opt_status("slashes", "on");
				g_opt.slash = 1;
				break;
			case O_SPACE:
				d_opt_status("status", "on");
				g_opt.space = 1;
				break;
			case O_SPECIAL:
				d_opt_status(opts_s[O_SPECIAL], "on");
				g_opt.special = 1;
				break;
			case O_HELP:
				printf("Help:\n");
			default:
				err_msg("Invalid Command-line Argument", -1);
		}*/
	}
}

bool isallowed(char chr) 
{
	bool ret = false;
	
	// if some allowed option matches the character,
	//    we flag it as temporarily true
	if ((g_opt.space && strchr(space_chr, chr) != NULL) ||
	     (g_opt.punct && strchr(punct_chr, chr) != NULL) ||
	     (g_opt.quote && strchr(quote_chr, chr) != NULL) ||
	     (g_opt.common && 
		  strchr(common_chr, chr) != NULL) ||
	     (g_opt.bracket && 
		  strchr(bracket_chr, chr) != NULL) ||
	     (g_opt.comput && 
	      strchr(computing_meaningful_chr, chr) != NULL) ||
	     (g_opt.slash && strchr(slash_chr, chr) != NULL) ||
	     (g_opt.math && strchr(math_chr, chr) != NULL) ||
	     (g_opt.special && 
		  strchr(special_chr, chr) != NULL))
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
	uint8_t *p = ptr;
	size_t ret = 0;
	
	if (p == NULL) // null pointer passed
		return ret;

	do
	{
		ret += fread(p, sizeof(uint8_t), 
				   times, stream);
		p += ret;
		if (++trials == g_opt.read_retries)
		       break;	
	}
	while ( ret < (times * sizeof(uint8_t)) && 
		(p - (uint8_t *) ptr) < times );
	
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
	while (!isalpha(i_chr) && !isallowed(i_chr)) {
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

	const char *const fmt[] = { "%02x", "%02X" };

	bzero(output, sizeof(output));

	if (digest == NULL){
		err_msg("Invalid digest pointer", errno);
		return;
	}

	while ( dg_ptr < dg_end && out_ptr < out_end && 
		out_ptr - output < g_opt.pwd_size)
	{
		if (*dg_ptr % 5 == 0) {
			*(out_ptr++) = process_chr(*dg_ptr++);
			if (out_ptr - output == g_opt.pwd_size)
			       break;	
			*(out_ptr++) = process_chr(*dg_ptr++);
			continue;
		}

		sprintf(out_ptr, fmt[*dg_ptr % 2], *dg_ptr);
		dg_ptr++;
		while (out_ptr < out_end && *out_ptr != 0 
		       && out_ptr - output < g_opt.pwd_size)
		{
			out_ptr++;
		}
	}

	printf("%.*s", (int) g_opt.pwd_size, output);

}

int main(int argc, char **argv)
{
	FILE *rdgen = NULL;
	uint8_t byte;
	size_t buf_size;
	uint8_t *buffer = NULL;
	struct sha512_ctx ctx;
	uint8_t digest[SHA512_DIGEST_SIZE];
	struct stat rdg_stt;

	bzero(&rdg_stt, sizeof(rdg_stt));

	parse_options(argc, argv);

	if (stat(g_opt.rand_gen, &rdg_stt) == -1)
		err_msg("Cannot stat random generator", errno);

	if (!S_ISCHR(rdg_stt.st_mode))
		err_msg("Random Number Generator is not a "
				"character device", -1);

	if (major(rdg_stt.st_rdev) != 1)
		fprintf(stderr, "Warning: %s (major=%d) isn't a "
						"memory device\n", g_opt.rand_gen,
						major(rdg_stt.st_mode));

	rdgen = fopen(g_opt.rand_gen, "r");

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

