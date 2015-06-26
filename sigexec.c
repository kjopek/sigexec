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
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/stat.h>
#include <sys/imgact.h>

#include <security/mac/mac_policy.h>

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

int 
sigexec_check_vnode_exec(struct ucred *cred,
	struct vnode *vp,
	struct label *label,
	struct image_params *img_params,
	struct label *img_label)
{
	struct thread *td;
	char buffer[255];
	int flags;
	int error;
	ssize_t resid;

	td = curthread;
	flags = FREAD;
	error = vn_open_vnode(vp, FREAD, cred, td, NULL);
	if (error == 0) {
		printf("SigEXEC: trying to check: %s\n", buffer);
		if (vp->v_type != VREG)
			error = 0;
		else
			error = vn_rdwr(UIO_READ, vp, buffer, 255, 0,
					UIO_SYSSPACE, IO_NODELOCKED, cred, NOCRED, &resid, td);
		VOP_UNLOCK(vp, 0);
		vn_close(vp, FREAD, cred, td);
	} else {
		printf("Error opening file: %d\n", error);
	}
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
