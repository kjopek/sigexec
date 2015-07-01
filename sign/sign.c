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
	fprintf(stderr, "Usage: sign [-c] [-v] -f keyfile file_to_sign\n");
}

void
print_hex(uint8_t *buffer, int len)
{
	int i;

	for (i = 0; i < len; ++i)
		fprintf(stderr, "%02hhx", buffer[i]);
	fprintf(stderr, "\n");
}

uint8_t *
hash_file(char *filename)
{
	FILE *fp;
	SHA256_CTX ctx;
	char buffer[4096];
	uint8_t *ret;
	size_t len;

	fp = fopen(filename, "rb");
	if (fp == NULL) {
		perror("fopen");
		return (NULL);
	}

	SHA256_Init(&ctx);
	while ((len = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
		SHA256_Update(&ctx, buffer, len);
	}

	fclose(fp);
	ret = malloc(uECC_BYTES);
	if (ret == NULL)
		return(NULL);

	SHA256_Final(ret, &ctx);
	return (ret);
}

int
main(int argc, char ** argv)
{
	int genkey, ch, verbose;
	FILE *fp;
	char *keyfile;
	uint8_t pubkey[uECC_BYTES * 2];
	uint8_t privkey[uECC_BYTES];
	uint8_t signature[uECC_BYTES * 2];
	uint8_t *hash;

	genkey = 0;
	keyfile = NULL;
	verbose = 0;
	while((ch = getopt(argc, argv, "cf:v")) != -1) {
		switch(ch) {
		case 'c':
			genkey = 1;
			break;
		case 'f':
			keyfile = optarg;
			break;
		case 'v':
			verbose = 1;
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
	if (verbose) {
		fprintf(stderr, "Public key:\t");
		print_hex(pubkey, uECC_BYTES * 2);
		fprintf(stderr, "Private key:\t");
		print_hex(privkey, uECC_BYTES);
	}
	fclose(fp);
	if (!genkey) {
		if (argc != 1) {
			fprintf(stderr, "Missing file to sign.");
			usage();
			return (2);
		}

		if ((hash = hash_file(argv[0])) == NULL) {
			fprintf(stderr, "Could not open file: %s\n", argv[0]);
			usage();
			return (3);
		}
		uECC_sign(privkey, hash, signature);	
		if (verbose) {
			fprintf(stderr, "Hash: ");
			print_hex(hash, uECC_BYTES);
			fprintf(stderr, "Signature: ");
			print_hex(signature, uECC_BYTES * 2);
		}
		if (extattr_set_file(argv[0], EXTATTR_NAMESPACE_SYSTEM, "signature",
		    signature, 2*uECC_BYTES) < 0) {
			fprintf(stderr, "Could not save signature.\n");
			return (4);
		}
		fprintf(stdout, "File %s was signed.\n", argv[0]);
		free(hash);
	}
	return (0);
}
