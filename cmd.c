// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	if (!dir)
		return false;

	char *path = get_word(dir);

	if (strlen(path) == 0)
		return false;

	if (!chdir(path))
		return true;

	return false;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	return SHELL_EXIT;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	if (!s)
		return -1;

	/* If builtin command, execute the command. */
	char *verb = get_word(s->verb);

	if (!strcmp(verb, "cd")) {
		if (s->out) {
			char *file_out = get_word(s->out);
			int flags = O_WRONLY | O_CREAT;

			if (s->io_flags == IO_REGULAR)
				flags |= O_TRUNC;

			if (s->io_flags == IO_OUT_APPEND)
				flags |= O_APPEND;

			int fd_out = open(file_out, flags, 0666);

			if (fd_out == -1)
				return 1;
		}

		if (shell_cd(s->params))
			return 0;
		return 1;
	}

	if (!strcmp(verb, "exit") || !strcmp(verb, "quit"))
		return shell_exit();

	/* If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	int status;

	if (s->verb->next_part) {
		char *eq = (char *)s->verb->next_part->string;

		if (!strcmp(eq, "=")) {
			char *env_var = (char *)s->verb->string;

			if (!env_var)
				return -1;

			char *env_val = get_word(s->verb->next_part->next_part);

			if (!env_val)
				return -1;

			status = setenv(env_var, env_val, 1);
			return status;
		}
	}

	/* If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */
	pid_t pid = fork();

	if (pid < 0)
		return -1;

	if (!pid) {
		int argc;
		char **argv = get_argv(s, &argc);

		if (s->in) {
			char *file_in = get_word(s->in);
			int fd_in = open(file_in, O_RDONLY);

			if (fd_in == -1)
				return -1;

			status = dup2(fd_in, STDIN_FILENO);
			if (status == -1)
				return -1;

			status = close(fd_in);
			if (status == -1)
				return -1;
		}

		if (s->out) {
			char *file_out = get_word(s->out);
			int flags = O_WRONLY | O_CREAT;

			if (s->io_flags == IO_REGULAR)
				flags |= O_TRUNC;

			if (s->io_flags == IO_OUT_APPEND)
				flags |= O_APPEND;

			int fd_out = open(file_out, flags, 0666);

			if (fd_out == -1)
				return -1;

			status = dup2(fd_out, STDOUT_FILENO);
			if (status == -1)
				return -1;

			status = close(fd_out);
			if (status == -1)
				return -1;
		}

		if (s->err) {
			char *file_err = get_word(s->err);
			int flags = O_WRONLY | O_CREAT;

			if (s->io_flags == IO_REGULAR)
				flags |= O_TRUNC;

			if (s->io_flags == IO_ERR_APPEND)
				flags |= O_APPEND;

			if (s->out && !strcmp(file_err, get_word(s->out))) {
				status = dup2(STDOUT_FILENO, STDERR_FILENO);
				if (status == -1)
					return -1;
			} else {
				int fd_err = open(file_err, flags, 0666);

				if (fd_err == -1)
					return -1;

				status = dup2(fd_err, STDERR_FILENO);
				if (status == -1)
					return -1;

				status = close(fd_err);
				if (status == -1)
					return -1;
			}
		}
		execvp(argv[0], argv);
		fprintf(stderr, "Execution failed for '%s'\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	waitpid(pid, &status, 0);

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	return -1;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* Execute cmd1 and cmd2 simultaneously. */
	pid_t pid1 = fork();

	if (pid1 < 0)
		return false;

	if (!pid1)
		exit(parse_command(cmd1, level + 1, father));

	pid_t pid2 = fork();

	if (pid2 < 0)
		return false;

	if (!pid2)
		exit(parse_command(cmd2, level + 1, father));

	int status1, status2;

	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	if (WIFEXITED(status1) && WIFEXITED(status2) &&
		(WEXITSTATUS(status1) == 0) && (WEXITSTATUS(status2) == 0))
		return true;

	return false;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int status;
	int pipefd[2];

	status = pipe(pipefd);

	if (status == -1)
		return false;

	pid_t pid1 = fork();

	if (pid1 < 0)
		return false;

	if (!pid1) {
		status = close(pipefd[0]);
		if (status == -1)
			return false;

		status = dup2(pipefd[1], STDOUT_FILENO);
		if (status == -1)
			return false;

		status = close(pipefd[1]);
		if (status == -1)
			return false;

		exit(parse_command(cmd1, level + 1, father));
	}

	pid_t pid2 = fork();

	if (pid2 < 0)
		return false;

	if (!pid2) {
		status = close(pipefd[1]);
		if (status == -1)
			return false;

		status = dup2(pipefd[0], STDIN_FILENO);
		if (status == -1)
			return false;

		status = close(pipefd[0]);
		if (status == -1)
			return false;

		exit(parse_command(cmd2, level + 1, father));
	}

	status = close(pipefd[0]);
	if (status == -1)
		return false;

	status = close(pipefd[1]);
	if (status == -1)
		return false;

	int status1, status2;

	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	if (WIFEXITED(status2) && (WEXITSTATUS(status2) == 0))
		return true;

	return false;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	if (!c)
		return -1;

	int status = 0;

	if (c->op == OP_NONE) {
		status = parse_simple(c->scmd, level + 1, c);
		return status;
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		status = parse_command(c->cmd1, level + 1, c);
		status = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PARALLEL:
		status = run_in_parallel(c->cmd1, c->cmd2, level + 1, c);
		if (status)
			return 0;
		return -1;

	case OP_CONDITIONAL_NZERO:
		status = parse_command(c->cmd1, level + 1, c);
		if (status)
			status = parse_command(c->cmd2, level + 1, c);

		break;

	case OP_CONDITIONAL_ZERO:
		status = parse_command(c->cmd1, level + 1, c);
		if (!status)
			status = parse_command(c->cmd2, level + 1, c);

		break;

	case OP_PIPE:
		status = run_on_pipe(c->cmd1, c->cmd2, level + 1, c);
		if (status)
			return 0;
		return -1;

	default:
		return SHELL_EXIT;
	}

	return status;
}
