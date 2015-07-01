/*
 * Copyright (C) 2011, 2012 Konrad Jopek <kjopek student.agh.edu.pl>
 * All right reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/acl.h>
#include <sys/kernel.h>
#include <sys/jail.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/stat.h>
#include <sys/imgact.h>
#include <sys/extattr.h>

#include <security/mac/mac_policy.h>
#include <crypto/sha2/sha2.h>

#include "uECC.h"

static uint8_t pubkey[2*uECC_BYTES] = {
/* TODO: add your public key for verification. The key below is only for
 * example!
 */
  0xd7, 0x5b, 0x0c, 0x52, 0x3e, 0xe2, 0xee, 0xcf, 0x0d, 0xd9, 0x0a, 0x80,
  0x60, 0x1d, 0xb5, 0xb9, 0x64, 0x10, 0xef, 0x38, 0x91, 0xf7, 0xae, 0xcf,
  0x19, 0x6d, 0x57, 0x71, 0xb5, 0x9f, 0xcd, 0x13, 0xca, 0x16, 0xf1, 0x68,
  0xd9, 0x33, 0x48, 0x5d, 0x68, 0xaa, 0x89, 0xb6, 0x56, 0xdd, 0xac, 0x98,
  0x2d, 0x35, 0xee, 0xbb, 0x72, 0x43, 0x42, 0xe9, 0x98, 0xb7, 0x06, 0xd3,
  0xc6, 0xdd, 0x31, 0xda
};

static void sigexec_init(struct mac_policy_conf *conf);
static void sigexec_destroy(struct mac_policy_conf *conf);
static int sigexec_check_vnode_exec(struct ucred *cred, struct vnode *vp,
	struct label *label, struct image_params *img_params,
	struct label *img_label);
static int sigexec_kld_check_load(struct ucred *cred, struct vnode *vp,
	struct label *vplabel);

#ifdef DEBUG
static void
print_hex(char *buffer, size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i)
		printf("%02hhx", buffer[i]);
	printf("\n");
}
#endif

static int
verify_file(struct ucred *cred, struct vnode *vp)
{
	char buffer[256];
	char hash[SHA256_DIGEST_LENGTH > uECC_BYTES ? SHA256_DIGEST_LENGTH : uECC_BYTES];
	char signature[2*uECC_BYTES];

	int error, len;
	ssize_t resid;
	off_t i, size;
	SHA256_CTX ctx;
	struct stat stat;

	i = 0;
	error = vn_stat(vp, &stat, cred, NOCRED, curthread);
	size = stat.st_size;
	if (error)
		return (EPERM);

	len = sizeof(signature);
	error = vn_extattr_get(vp, IO_NODELOCKED, EXTATTR_NAMESPACE_SYSTEM, 
	    "signature", &len, signature, curthread);
	if (error)
		return (0); /* permissive */

#ifdef DEBUG
	printf("Signature: ");
	print_hex(signature, sizeof(signature));
#endif
	SHA256_Init(&ctx);
	while(i < size && !error) {
		len = size - i > sizeof(buffer) ? sizeof(buffer) : size - i;
		error = vn_rdwr(UIO_READ, vp, buffer, len, i,
		    UIO_SYSSPACE, IO_NODELOCKED, cred, NOCRED,
		    &resid, curthread);
		SHA256_Update(&ctx, buffer, len);
		i += len;
	}
	if (error)
		return (EPERM);

	SHA256_Final(hash, &ctx);
#ifdef DEBUG
	printf("Hash: ");
	print_hex(hash, sizeof(hash));
#endif
	if (!uECC_verify(pubkey, hash, signature))
		return (EPERM);

	return (0);
}

static void
sigexec_init(struct mac_policy_conf *conf)
{
	printf("SigEXEC initialized\n");
}

static void
sigexec_destroy(struct mac_policy_conf *conf)
{
	printf("SigEXEC destroyed\n");
}

static int 
sigexec_check_vnode_exec(struct ucred *cred, struct vnode *vp,
    struct label *label, struct image_params *img_params,
    struct label *img_label)
{
	return (verify_file(cred, vp));
}

static int sigexec_kld_check_load(struct ucred *cred, struct vnode *vp,
	struct label *vplabel)
{
	return (verify_file(cred, vp));
}
static struct mac_policy_ops sigexec_ops =
{
	.mpo_init = sigexec_init,
	.mpo_destroy = sigexec_destroy,
	.mpo_vnode_check_exec = sigexec_check_vnode_exec,
	.mpo_kld_check_load = sigexec_kld_check_load
};

MAC_POLICY_SET(&sigexec_ops, mac_sigexec, "SigEXEC module",
	MPC_LOADTIME_FLAG_UNLOADOK, NULL);
MODULE_DEPEND(mac_sigexec, crypto, 1, 1, 1);
