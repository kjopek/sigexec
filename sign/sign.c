#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sha256.h>
#include "uECC.h"

void
usage(void)
{
	fprintf(stderr, "Usage: sign [-c] -f keyfile file_to_sign\n");
}

int
main(int argc, char ** argv)
{
	int genkey, ch;
	char *keyfile;

	genkey = 0;
	keyfile = NULL;
	while((ch = getopt(argc, argv, "cf:")) != -1) {
		switch(ch) {
		case 'c':
			genkey = 1;
			break;
		case 'f':
			keyfile = optarg;
			break;
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	
	if (keyfile == NULL) {
		fprintf(stderr, "Key file was not specified");
		usage();
		return (1);
	}

	if (!genkey && argc != 1) {
		fprintf(stderr, "Missing file_to_sign");
		usage();
		return (2);
	}

	

	return (0);
}
