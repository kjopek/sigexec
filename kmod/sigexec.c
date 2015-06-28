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

};

void sigexec_init(struct mac_policy_conf *conf);
void sigexec_destroy(struct mac_policy_conf *conf);
int sigexec_check_vnode_exec(struct ucred *cred, struct vnode *vp,
	struct label *label, struct image_params *img_params,
	struct label *img_label);

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

	printf("vn_extattr_get successful\n");
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
	if (!uECC_verify(pubkey, hash, signature))
		return (EPERM);

	return (0);

}

void
sigexec_init(struct mac_policy_conf *conf)
{
	printf("SigEXEC initialized\n");
}

void
sigexec_destroy(struct mac_policy_conf *conf)
{
	printf("SigEXEC destroyed\n");
}


int 
sigexec_check_vnode_exec(struct ucred *cred, struct vnode *vp,
    struct label *label, struct image_params *img_params,
    struct label *img_label)
{
	return (verify_file(cred, vp));
}

static struct mac_policy_ops sigexec_ops =
{
	.mpo_init = sigexec_init,
	.mpo_destroy = sigexec_destroy,
	.mpo_vnode_check_exec = sigexec_check_vnode_exec,
};

MAC_POLICY_SET(&sigexec_ops, mac_sigexec, "SigEXEC module",
	MPC_LOADTIME_FLAG_UNLOADOK, NULL);
MODULE_DEPEND(mac_sigexec, crypto, 1, 1, 1);
