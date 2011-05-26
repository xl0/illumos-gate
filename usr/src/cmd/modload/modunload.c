/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/modctl.h>
#include <zone.h>

void	usage();
void	exec_userfile(char *execfile, int id, char **envp);
int	name_to_id(char *modname);
void	do_unload(int id, char *modname, char *exectfile, char *envp[]);

extern void fatal(char *fmt, ...);
extern void error(char *fmt, ...);

/*
 * Unload a loaded module.
 */
int
main(int argc, char *argv[], char *envp[])
{
	int i;
	int id = -1;
	char *execfile = NULL;
	int opt;
	extern char *optarg;

	while ((opt = getopt(argc, argv, "i:e:")) != -1) {
		switch (opt) {
		case 'i':
			if (sscanf(optarg, "%d", &id) != 1)
				fatal("Invalid id %s\n", optarg);
			break;
		case 'e':
			execfile = optarg;
		}
	}

	if (getzoneid() != GLOBAL_ZONEID) {
		fatal("modunload can only be run from the global zone\n");
	}

	if (id >= 0) {
		do_unload(id, NULL, execfile, envp);
	} else if (optind >= argc) {
		/* Eiter pass id with -i, or a module name as arg. Or both. */
		usage();
	}

	/*
	 * If id is not specified explicitly, we loop over
	 * the given module names.
	 */
	for (i = optind; i < argc; i++) {
		id = name_to_id(argv[i]);
		if (id < 0) {
			fprintf(stderr, "Module '%s' not loaded\n", argv[i]);
			continue;
		}

		do_unload(id, argv[i], execfile, envp);
	}

	return (0); /* success */
}

int
name_to_id(char *modname)
{
	struct modinfo modinfo;
	int id = -1;

	modinfo.mi_id = modinfo.mi_nextid = id = -1;
	modinfo.mi_info = MI_INFO_ALL | MI_INFO_CNT;

	for (;;) {
		if (modctl(MODINFO, id, &modinfo) < 0)
			break;

		id = modinfo.mi_id;

		if (!(modinfo.mi_state & MI_LOADED))
			continue;

		if (!(strncmp(modinfo.mi_name, modname, MODMAXNAMELEN)))
			return (id);
	}

	return (-1);
}

/*
 * Unload a module. Optionally, run execfile.
 */
void
do_unload(int id, char *modname, char *execfile, char *envp[])
{
	int child;
	int status;

	if (execfile) {
		child = fork();
		if (child == -1)
			error("can't fork %s", execfile);
		else if (child == 0)
			exec_userfile(execfile, id, envp);
		else {
			(void) wait(&status);
			if (status != 0) {
				(void) printf("%s returned error %d.\n",
				    execfile, status);
				(void) exit(status >> 8);
			}
		}
	}

	if (modctl(MODUNLOAD, id) < 0) {
		if (errno == EPERM) {
			fatal("Insufficient privileges to"
					"unload a module\n");
		} else if (id != 0) {
			if (modname) {
				fprintf(stderr,
					"can't unload module '%s': %s\n",
					modname, strerror(errno));
			} else {
				fprintf(stderr,
					"can't unload module (id %d): %s\n",
					id, strerror(errno));
			}
		}
	}
}

/*
 * exec the user file.
 */
void
exec_userfile(char *execfile, int id, char **envp)
{
	struct modinfo modinfo;

	char modid[8];
	char mod0[8];

	modinfo.mi_id = modinfo.mi_nextid = id;
	modinfo.mi_info = MI_INFO_ONE;
	if (modctl(MODINFO, id, &modinfo) < 0)
		error("can't get module information");

	(void) sprintf(modid, "%d", id);
	(void) sprintf(mod0, "%d", modinfo.mi_msinfo[0].msi_p0);

	(void) execle(execfile, execfile, modid, mod0, NULL, envp);

	error("couldn't exec %s\n", execfile);
}


void
usage()
{
	fatal("usage: modunload [-i <module_id>]"
		"[-e <exec_file>] [module_name ... ]\n");
}
