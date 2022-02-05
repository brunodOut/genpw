# Info

genpwd is a small  code  in C  that,  as the name suggests,
generates passwords. At  first I coded it since one browser
I am using does not generate passwords for me and the other
generated ones that I dislike because some characters won't
allow some special characters.

genpwd is supposed to be in  hand and useful someday in the
future, but at first it's  only  useful for me. It was also
intended to help me learn to code again, after 10 years, so
don't expect the code to be  good. I was also trying to use
the GNU getopt_long and  getsubopt  just to remember how to
use it, and for the case of getsubopt I failed it until now
.

# Build

There is no Makefile or configuration script. To compile it
you will need:
- Make sure you have  nettle,  including headers, installed 
  and available in your INCLUDE_PATH.
- gcc

\$ `gcc -lnettle -o genpwd genpwd.c`

If you want debug support, try:

\$ `gcc -lnettle -D__DEBUG__ -g3 -o genpwd genpwd.c`

# Usage

There are neither helps nor docs yet, but a list of cmdline
options is available in 
(genpwd-options.txt)[genpwd-options.txt] and into the code,
so serve yourself.

# Todo

There are lots of stuff to do to make it useful for humans,
like a help regarding the options and other improvements:
- Proper documentation
- Syllabic password  generation  (I'm a linguist and should
be capable of handling that)
- Better default values
- Better options, like both disabling and enabling
- Fix or remove the getsubopt use
(no necessarily in that order)

# Future

I plan to also  develop  a  GUI  application  to manage and
generate passwords and 2FA authentication information. But,
one step at each time! I  also  don't plan to dedicate time
enough to develop/maintain it regularly.
