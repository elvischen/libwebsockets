/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "private-lib-core.h"

#if defined(WIN32) || defined(_WIN32)
#else
#include <sys/wait.h>
#endif

static struct lws *
lws_create_basic_wsi(struct lws_context *context, int tsi,
		     const struct lws_role_ops *ops)
{
	struct lws *new_wsi;

	if (!context->vhost_list)
		return NULL;

	if ((unsigned int)context->pt[tsi].fds_count ==
	    context->fd_limit_per_thread - 1) {
		lwsl_err("no space for new conn\n");
		return NULL;
	}

	new_wsi = lws_zalloc(sizeof(struct lws), "new wsi");
	if (new_wsi == NULL) {
		lwsl_err("Out of memory for new connection\n");
		return NULL;
	}

	new_wsi->tsi = tsi;
	new_wsi->context = context;
	new_wsi->pending_timeout = NO_PENDING_TIMEOUT;
	new_wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;

	/* initialize the instance struct */

	lws_role_transition(new_wsi, 0, LRS_ESTABLISHED, ops);

	new_wsi->hdr_parsing_completed = 0;
	new_wsi->position_in_fds_table = LWS_NO_FDS_POS;

	/*
	 * these can only be set once the protocol is known
	 * we set an unestablished connection's protocol pointer
	 * to the start of the defauly vhost supported list, so it can look
	 * for matching ones during the handshake
	 */

	new_wsi->user_space = NULL;
	new_wsi->desc.sockfd = LWS_SOCK_INVALID;
	context->count_wsi_allocated++;

	return new_wsi;
}

void
lws_spawn_piped_destroy(struct lws_context *context, int tsi,
			struct lws_spawn_piped *lsp)
{
	int n;

	for (n = 0; n < 3; n++) {
		if (lsp->pipe_fds[n][!!(n == 0)] == 0)
			lwsl_err("ZERO FD IN CGI CLOSE");

		if (lsp->pipe_fds[n][!!(n == 0)] >= 0) {
			close(lsp->pipe_fds[n][!!(n == 0)]);
			lsp->pipe_fds[n][!!(n == 0)] = LWS_SOCK_INVALID;
		}
	}

	lws_dll2_remove(&lsp->dll);
	lws_sul_schedule(context, tsi, &lsp->sul, NULL, LWS_SET_TIMER_USEC_CANCEL);
}

int
lws_spawn_piped_kill_child_process(struct lws_spawn_piped *lsp)
{
	int status, n;

	if (lsp->child_pid <= 0)
		return 1;

	n = waitpid(lsp->child_pid, &status, WNOHANG);
	if (n > 0) {
		lwsl_debug("%s: PID %d reaped\n", __func__, lsp->child_pid);
		goto handled;
	}

	/* kill the process group */
	n = kill(-lsp->child_pid, SIGTERM);
	lwsl_debug("%s: SIGTERM child PID %d says %d (errno %d)\n", __func__,
		   lsp->child_pid, n, errno);
	if (n < 0) {
		/*
		 * hum seen errno=3 when process is listed in ps,
		 * it seems we don't always retain process grouping
		 *
		 * Direct these fallback attempt to the exact child
		 */
		n = kill(lsp->child_pid, SIGTERM);
		if (n < 0) {
			n = kill(lsp->child_pid, SIGPIPE);
			if (n < 0) {
				n = kill(lsp->child_pid, SIGKILL);
				if (n < 0)
					lwsl_info("%s: SIGKILL PID %d "
						 "failed errno %d "
						 "(maybe zombie)\n", __func__,
						 lsp->child_pid, errno);
			}
		}
	}

	/* He could be unkillable because he's a zombie */

	n = 1;
	while (n > 0) {
		n = waitpid(-lsp->child_pid, &status, WNOHANG);
		if (n > 0)
			lwsl_debug("%s: reaped PID %d\n", __func__, n);
		if (n <= 0) {
			n = waitpid(lsp->child_pid, &status, WNOHANG);
			if (n > 0)
				lwsl_debug("%s: reaped PID %d\n", __func__, n);
		}
	}

handled:
	lsp->child_pid = -1;

	return 0;
}

/*
 * Deals with spawning a subprocess and executing it securely with stdin/out/err
 * diverted into pipes
 */

int
lws_spawn_piped(struct lws_dll2_owner *owner, struct lws_vhost *vh, int tsi,
		struct lws *opt_parent, struct lws_spawn_piped *lsp,
		const char * const *exec_array, char **env_array,
		const char *pcon, lws_usec_t timeout, sul_cb_t timeout_cb)
{
	const struct lws_protocols *pcol = vh->context->vhost_list->protocols;
	int n, m;

	if (pcon)
		pcol = lws_vhost_name_to_protocol(vh, pcon);
	if (!pcol) {
		lwsl_err("%s: unknown protocol %s\n", __func__,
			 pcon ? pcon : "default");

		return -1;
	}

	/*
	 * Prepare the stdin / out / err pipes
	 */

	for (n = 0; n < 3; n++) {
		lsp->pipe_fds[n][0] = -1;
		lsp->pipe_fds[n][1] = -1;
	}

	/* create pipes for [stdin|stdout] and [stderr] */

	for (n = 0; n < 3; n++)
		if (pipe(lsp->pipe_fds[n]) == -1)
			goto bail1;

	/* create wsis for each stdin/out/err fd */

	for (n = 0; n < 3; n++) {
		lsp->stdwsi[n] = lws_create_basic_wsi(vh->context, tsi,
						      lsp->ops ? lsp->ops :
						      &role_ops_raw_file);
		if (!lsp->stdwsi[n]) {
			lwsl_err("%s: unable to create lsp stdwsi\n", __func__);
			goto bail2;
		}
		lsp->stdwsi[n]->lsp_channel = n;
		lws_vhost_bind_wsi(vh, lsp->stdwsi[n]);
		lsp->stdwsi[n]->protocol = pcol;

		lwsl_debug("%s: lsp stdwsi %p: pipe idx %d -> fd %d / %d\n", __func__,
			   lsp->stdwsi[n], n, lsp->pipe_fds[n][!!(n == 0)],
			   lsp->pipe_fds[n][!(n == 0)]);

		/* read side is 0, stdin we want the write side, others read */

		lsp->stdwsi[n]->desc.sockfd = lsp->pipe_fds[n][!!(n == 0)];
		if (fcntl(lsp->pipe_fds[n][!!(n == 0)], F_SETFL, O_NONBLOCK) < 0) {
			lwsl_err("%s: setting NONBLOCK failed\n", __func__);
			goto bail2;
		}
	}

	for (n = 0; n < 3; n++) {
		if (vh->context->event_loop_ops->sock_accept)
			if (vh->context->event_loop_ops->sock_accept(lsp->stdwsi[n]))
				goto bail3;

		if (__insert_wsi_socket_into_fds(vh->context, lsp->stdwsi[n]))
			goto bail3;
		if (opt_parent) {
			lsp->stdwsi[n]->parent = opt_parent;
			lsp->stdwsi[n]->sibling_list = opt_parent->child_list;
			opt_parent->child_list = lsp->stdwsi[n];
		}
	}

	if (lws_change_pollfd(lsp->stdwsi[LWS_STDIN], LWS_POLLIN, LWS_POLLOUT))
		goto bail3;
	if (lws_change_pollfd(lsp->stdwsi[LWS_STDOUT], LWS_POLLOUT, LWS_POLLIN))
		goto bail3;
	if (lws_change_pollfd(lsp->stdwsi[LWS_STDERR], LWS_POLLOUT, LWS_POLLIN))
		goto bail3;

	lwsl_debug("%s: fds in %d, out %d, err %d\n", __func__,
		   lsp->stdwsi[LWS_STDIN]->desc.sockfd,
		   lsp->stdwsi[LWS_STDOUT]->desc.sockfd,
		   lsp->stdwsi[LWS_STDERR]->desc.sockfd);

	/* we are ready with the redirection pipes... run the thing */
#if !defined(LWS_HAVE_VFORK) || !defined(LWS_HAVE_EXECVPE)
	lsp->child_pid = fork();
#else
	lsp->child_pid = vfork();
#endif
	if (lsp->child_pid < 0) {
		lwsl_err("%s: fork failed, errno %d", __func__, errno);
		goto bail3;
	}

#if defined(__linux__)
	prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif

	if (lsp->do_setpgrp)
		/* stops non-daemonized main processess getting SIGINT
		 * from TTY */
		setpgrp();

	if (lsp->child_pid) {

		/* we are the parent process */

		lwsl_info("%s: lsp %p spawned PID %d\n", __func__, lsp,
			  lsp->child_pid);

		/*
		 *  close:                stdin:r, stdout:w, stderr:w
		 * hide from other forks: stdin:w, stdout:r, stderr:r
		 */
		for (n = 0; n < 3; n++) {
			lws_plat_apply_FD_CLOEXEC(lsp->pipe_fds[n][!!(n == 0)]);
			close(lsp->pipe_fds[n][!(n == 0)]);
		}

		if (owner)
			lws_dll2_add_head(&lsp->dll, owner);

		if (timeout)
			lws_sul_schedule(vh->context, tsi,
					 &lsp->sul, timeout_cb, timeout);

		return 0;
	}

	/* somewhere we can at least read things and enter it */
	if (chdir("/tmp"))
		lwsl_notice("%s: Failed to chdir\n", __func__);

	/* We are the forked process, redirect and kill inherited things.
	 *
	 * Because of vfork(), we cannot do anything that changes pages in
	 * the parent environment.  Stuff that changes kernel state for the
	 * process is OK.  Stuff that happens after the execvpe() is OK.
	 */

	for (m = 0; m < 3; m++) {
		if (dup2(lsp->pipe_fds[m][!(m == 0)], m) < 0) {
			lwsl_err("%s: stdin dup2 failed\n", __func__);
			goto bail3;
		}
		close(lsp->pipe_fds[m][0]);
		close(lsp->pipe_fds[m][1]);
	}

#if !defined(LWS_HAVE_VFORK) || !defined(LWS_HAVE_EXECVPE)
	for (m = 0; m < n; m++) {
		char *p = strchr(env_array[m], '=');
		*p++ = '\0';
		setenv(env_array[m], p, 1);
	}
	execvp(exec_array[0], (char * const *)&exec_array[0]);
#else
	execvpe(exec_array[0], (char * const *)&exec_array[0], &env_array[0]);
#endif

	exit(1);

bail3:

	while (--n >= 0)
		__remove_wsi_socket_from_fds(lsp->stdwsi[n]);
bail2:
	for (n = 0; n < 3; n++)
		if (lsp->stdwsi[n])
			__lws_free_wsi(lsp->stdwsi[n]);

bail1:
	for (n = 0; n < 3; n++) {
		if (lsp->pipe_fds[n][0] >= 0)
			close(lsp->pipe_fds[n][0]);
		if (lsp->pipe_fds[n][1] >= 0)
			close(lsp->pipe_fds[n][1]);
	}

	lwsl_err("%s: failed\n", __func__);

	return -1;
}
