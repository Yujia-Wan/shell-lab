/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * This program implements a Linux shell program that
 * supports some built-in commands, running the job in
 * background/foreground, handing SIGINT, SIGTSTP and
 * SIGCHLD signals, and I/O redirection.
 *
 * @author Yujia Wang <yujiawan@andrew.cmu.edu>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);
void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

/**
 * @brief Executes shell's evaluating loop for command lines.
 *
 * Parses command lines, initializes job list, installs signal handlers,
 * and evaluates and executes command lines.
 *
 * @param[in] argc Number of arguments
 * @param[in] argv Pointer to array of arguments
 * @return 0 on normal return status, nonzero on error
 *
 */
int main(int argc, char **argv) {
    char c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv("MY_ENV=42") < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/**
 * @brief Executes built-in commands 'bg' and 'fg'
 *
 * The 'bg job' command resumes job by sending it a SIGCONT signal and then
 * runs it in the background. The 'fg job' command resumes job by sending it
 * a SIGCONT signal and then runs it in the foreground.
 *
 * @param[in] token Pointer to a cmdline_tokens structure, which will
 *                  be populated with the parsed tokens.
 */
void bgfg(struct cmdline_tokens token) {
    // invalid command line
    if (token.argc != 2) {
        sio_printf("%s command requires PID or %%jobid argument\n",
                   token.argv[0]);
        return;
    }

    pid_t pid;
    jid_t jid;

    sigset_t mask_all, prev_one;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev_one);

    if (token.argv[1][0] == '%') {
        // the job argument is a JID
        jid = atoi(&token.argv[1][1]);
        if (jid == 0) { // invalid job argument
            sio_printf("%s: argument must be a PID or %%jobid\n",
                       token.argv[0]);
            sigprocmask(SIG_SETMASK, &prev_one, NULL);
            return;
        }
        if (!job_exists(jid)) { // job does not exist
            sio_printf("%%%d: No such job\n", (int)jid);
            sigprocmask(SIG_SETMASK, &prev_one, NULL);
            return;
        }
        pid = job_get_pid(jid);
    } else {
        // the job argument is a PID
        pid = atoi(&token.argv[1][0]);
        if (pid == 0) { // invalid job argument
            sio_printf("%s: argument must be a PID or %%jobid\n",
                       token.argv[0]);
            sigprocmask(SIG_SETMASK, &prev_one, NULL);
            return;
        }
        jid = job_from_pid(pid);
        if (jid == 0) { // no job with given PID exists
            sio_printf("%d: No such job\n", (int)pid);
            sigprocmask(SIG_SETMASK, &prev_one, NULL);
            return;
        }
    }

    job_state state = job_get_state(jid);
    if (token.builtin == BUILTIN_BG) {
        // bg job
        if (state == FG || state == UNDEF) {
            // invalid command line for foreground or undefined job
            sio_printf("bg job error\n");
            sigprocmask(SIG_SETMASK, &prev_one, NULL);
            return;
        }
        if (state == ST) {
            // run the job in background
            job_set_state(jid, BG);
            kill(-pid, SIGCONT);
            sio_printf("[%d] (%d) %s\n", (int)jid, (int)pid,
                       job_get_cmdline(jid));
            sigprocmask(SIG_SETMASK, &prev_one, NULL);
            return;
        }
    } else {
        // fg job
        if (state == UNDEF) {
            // invalid command line for undefined job
            sio_printf("fg job error\n");
            sigprocmask(SIG_SETMASK, &prev_one, NULL);
            return;
        }
        if (state == BG || state == ST) {
            // run the job in foreground
            if (fg_job() != 0) {
                sio_printf("a foreground job already exists\n");
                sigprocmask(SIG_SETMASK, &prev_one, NULL);
                return;
            }
            job_set_state(jid, FG);
            kill(-pid, SIGCONT);
            // wait for the current foreground job's termination
            while (fg_job() != 0) {
                sigsuspend(&prev_one);
            }
            sigprocmask(SIG_SETMASK, &prev_one, NULL);
            return;
        }
    }
    sigprocmask(SIG_SETMASK, &prev_one, NULL);
}

/**
 * @brief Check if the command line is built-in command
 *
 * Firstly checks if the command line is built-in command, and then executes
 * this command line if it is a built-in command.
 *
 * @param[in] token Pointer to a cmdline_tokens structure, which will
 *                  be populated with the parsed tokens.

 * @return 1 if the command line is a built-in command; 0 if not a built-in
 command
 */
int builtin_command(struct cmdline_tokens token) {
    sigset_t mask_all, prev_one;
    sigfillset(&mask_all);

    if (token.builtin == BUILTIN_QUIT) {
        exit(0);
    }

    if (token.builtin == BUILTIN_JOBS) {
        // initialize the default file descriptor as 'STDOUT_FILENO'
        int output_fd = STDOUT_FILENO;
        if (token.outfile != NULL) {
            // a valid file descriptor open for writing
            output_fd =
                open(token.outfile, O_CREAT | O_TRUNC | O_WRONLY,
                     S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
            if (output_fd == -1) {
                // invalide output file descriptor
                if (errno == ENOENT) {
                    sio_printf("%s : No such file or directory\n",
                               token.outfile);
                }
                if (errno == EACCES) {
                    sio_printf("%s: Permission denied\n", token.outfile);
                }
                return 1;
            }
        }

        sigprocmask(SIG_BLOCK, &mask_all, &prev_one);
        list_jobs(output_fd);

        // close file if it is not STDOUT_FILENO
        if (output_fd != STDOUT_FILENO) {
            if (close(output_fd) < 0) {
                perror("close error");
                exit(1);
            }
        }
        sigprocmask(SIG_SETMASK, &prev_one, NULL);
        return 1;
    }

    if (token.builtin == BUILTIN_BG || token.builtin == BUILTIN_FG) {
        // execute bg/fg command
        bgfg(token);
        return 1;
    }
    return 0;
}

/**
 * @brief Evaluates the command line and executes corresponding command
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 *
 * @param[in] cmdline The command line to parse
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;

    pid_t pid;
    jid_t jid;
    job_state state;

    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    // set job state as background
    if (parse_result == PARSELINE_BG) {
        state = BG;
    }

    // set job state as foreground
    if (parse_result == PARSELINE_FG) {
        state = FG;
    }

    sigset_t mask_all, prev_one;
    sigfillset(&mask_all);
    if (!builtin_command(token)) {
        sigprocmask(SIG_BLOCK, &mask_all, &prev_one);
        if ((pid = fork()) == 0) { // Child runs user job
            sigprocmask(SIG_SETMASK, &prev_one, NULL);

            // put the child in a new process group whose group ID is identical
            // to the child's PID ensure that there will be only one process,
            // your shell, in the foreground preocess group
            setpgid(0, 0);

            if (token.infile != NULL) {
                // input redirection
                int input_fd = open(token.infile, O_RDONLY);
                if (input_fd == -1) {
                    // open file failed
                    if (errno == ENOENT) {
                        sio_printf("%s : No such file or directory\n",
                                   token.infile);
                    }
                    if (errno == EACCES) {
                        sio_printf("%s: Permission denied\n", token.infile);
                    }
                    exit(1);
                }
                if (dup2(input_fd, STDIN_FILENO) < 0) {
                    perror("dup2 error");
                    exit(1);
                }
                if (close(input_fd) < 0) {
                    perror("close error");
                    exit(1);
                }
            }

            if (token.outfile != NULL) {
                // output redirection
                int output_fd = open(
                    token.outfile, O_CREAT | O_TRUNC | O_WRONLY,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
                if (output_fd == -1) {
                    // open file failed
                    if (errno == ENOENT) {
                        sio_printf("%s : No such file or directory\n",
                                   token.outfile);
                    }
                    if (errno == EACCES) {
                        sio_printf("%s: Permission denied\n", token.outfile);
                    }
                    exit(1);
                }
                if (dup2(output_fd, STDOUT_FILENO) < 0) {
                    perror("dup2 error");
                    exit(1);
                }
                if (close(output_fd) < 0) {
                    perror("close error");
                    exit(1);
                }
            }

            // execute the command line
            if (execve(token.argv[0], token.argv, environ) < 0) {
                // I/O redirection error handling
                if (errno == ENOENT) {
                    sio_printf("%s: No such file or directory\n", cmdline);
                }
                if (errno == EACCES) {
                    sio_printf("%s: Permission denied\n", cmdline);
                }
                exit(1);
            }
        }

        sigprocmask(SIG_BLOCK, &mask_all, NULL);
        jid = add_job(pid, state, cmdline);

        if (state != BG) {
            // wait for the current foreground job's termination
            while (fg_job()) {
                sigsuspend(&prev_one);
            }
        } else {
            // command prompt after running the background job command
            sio_printf("[%d] (%d) %s\n", (int)jid, (int)pid, cmdline);
        }
        sigprocmask(SIG_SETMASK, &prev_one, NULL);
    }
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief Handles SIGSHLD signals of all child processes
 *
 * @param[in] sig SIGCHLD signal
 */
void sigchld_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_one;
    pid_t pid;
    jid_t jid;
    int status;

    sigfillset(&mask_all);
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        sigprocmask(SIG_BLOCK, &mask_all, &prev_one);
        // normal return
        if (WIFEXITED(status)) {
            jid = job_from_pid(pid);
            delete_job(jid);
        }

        // handle terminated child
        if (WIFSIGNALED(status)) {
            jid = job_from_pid(pid);
            delete_job(jid);
            sio_printf("Job [%d] (%d) terminated by signal %d\n", (int)jid,
                       (int)pid, WTERMSIG(status));
        }

        // handle stopped child
        if (WIFSTOPPED(status)) {
            jid = job_from_pid(pid);
            job_set_state(jid, ST);
            sio_printf("Job [%d] (%d) stopped by signal %d\n", (int)jid,
                       (int)pid, WSTOPSIG(status));
        }
        sigprocmask(SIG_SETMASK, &prev_one, NULL);
    }
    errno = olderrno;
}

/**
 * @brief Handles SIGINT signal sent by Ctrl-C.
 *
 * @param[in] sig SIGINT signal
 */
void sigint_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_one;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev_one);
    jid_t jid = fg_job();
    // if foreground job exists, terminate the job
    if (jid) {
        pid_t pid = job_get_pid(jid);
        // send SIGINT signal to the process group
        kill(-pid, SIGINT);
    }
    sigprocmask(SIG_SETMASK, &prev_one, NULL);
    errno = olderrno;
}

/**
 * @brief Handles SIGTSTP signal sent by Ctrl-Z.
 *
 * @param[in] sig SIGTSTP signal
 */
void sigtstp_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_one;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev_one);
    jid_t jid = fg_job();
    // if foreground job exists, stop the job
    if (jid) {
        pid_t pid = job_get_pid(jid);
        // send SIGTSTP signal to the process group
        kill(-pid, SIGTSTP);
    }
    sigprocmask(SIG_SETMASK, &prev_one, NULL);
    errno = olderrno;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
