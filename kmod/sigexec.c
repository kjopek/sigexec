/*
 * Copyright (C) 2011, 2012 Konrad Jopek <kjopek student.agh.edu.pl>\
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

#include <security/mac/mac_policy.h>
#include <crypto/sha2/sha2.h>

void sigexec_init(struct mac_policy_conf *conf);
void sigexec_destroy(struct mac_policy_conf *conf);
int sigexec_check_vnode_exec(struct ucred *cred,
	struct vnode *vp, struct label *label, struct image_params *img_params,
	struct label *img_label);

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

static void
print_hex(char *buffer, size_t len)
{
	size_t i;

	i = 0;
	for (i = 0; i < len; ++i) {
		printf("%02hhx", buffer[i]);
	}
	printf("\n");
}

int 
sigexec_check_vnode_exec(struct ucred *cred,
	struct vnode *vp,
	struct label *label,
	struct image_params *img_params,
	struct label *img_label)
{
	char buffer[256];
	char hash[SHA256_DIGEST_LENGTH];
	int error;
	ssize_t resid;
	SHA256_CTX ctx;
	struct stat stat;
	off_t i, size;

	SHA256_Init(&ctx);

	error = vn_stat(vp, &stat, cred, NOCRED, curthread);
	if (error)
		return (0);

	size = stat.st_size;
	printf("File size: %llu\n", (unsigned long long) size);
	for (i = 0; i < size && !error; i += sizeof(buffer)) {
		error = vn_rdwr(UIO_READ, vp, buffer, sizeof(buffer), i,
		    UIO_SYSSPACE, IO_NODELOCKED, cred, NOCRED,
		    &resid, curthread);
		SHA256_Update(&ctx, buffer, sizeof(buffer));
	}

	i = size - size % sizeof(buffer);
	error = vn_rdwr(UIO_READ, vp, buffer, size % sizeof(buffer), i,
	    UIO_SYSSPACE, IO_NODELOCKED, cred, NOCRED, &resid, curthread);
	SHA256_Update(&ctx, buffer, sizeof(buffer));
	SHA256_Final(hash, &ctx);
	if (error)
		printf("Error: %d\n", error);
	else
		print_hex(hash, sizeof(hash));

	return (0);
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
