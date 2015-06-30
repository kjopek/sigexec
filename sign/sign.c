#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sha256.h>
#include "uECC.h"

#include <sys/types.h>
#include <sys/extattr.h>

void
usage(void)
{
	fprintf(stderr, "Usage: sign [-c] -f keyfile file_to_sign\n");
}

int
main(int argc, char ** argv)
{
	int genkey, ch;
	FILE *fp;
	char *keyfile;
	uint8_t hash[uECC_BYTES > 65 ? uECC_BYTES : 65];
	uint8_t pubkey[uECC_BYTES * 2];
	uint8_t privkey[uECC_BYTES];
	uint8_t signature[uECC_BYTES * 2];

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
		fprintf(stderr, "Key file was not specified.\n");
		usage();
		return (1);
	}

	fp = fopen(keyfile, genkey ? "wb" : "rb");
	if (fp == NULL) {
		fprintf(stderr, "Cannot open: %s.\n", keyfile);
		usage();
		return (1);
	}

	if (genkey) {
		uECC_make_key(pubkey, privkey);
		fwrite(pubkey, sizeof(pubkey), 1, fp);
		fwrite(privkey,sizeof(privkey), 1, fp);
	} else {
		fread(pubkey, sizeof(pubkey), 1, fp);
		fread(privkey, sizeof(privkey), 1, fp);
	}
	fclose(fp);

	if (!genkey && argc != 1) {
		fprintf(stderr, "Missing file to sign.");
		usage();
		return (2);
	}

	if (SHA256_File(argv[0], (char*) hash) == NULL) {
		fprintf(stderr, "Could not open file: %s\n", argv[0]);
		usage();
		free(hash);
		return (3);
	}
	uECC_sign(privkey, hash, signature);	

	if (extattr_set_file(argv[0], EXTATTR_NAMESPACE_SYSTEM, "signature",
	    signature, uECC_BYTES) < 0) {
		fprintf(stderr, "Could not save signature.\n");
		return (4);
	}
	fprintf(stdout, "File %s was signed.\n", argv[0]);
	return (0);
}
