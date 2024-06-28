#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include "log.h"
#include "blocking.h"
#include "dupforkexec.h"

void defaultsignals(void) {

    long long i;

    for (i = 1; i < 32; ++i) { signal(i, SIG_DFL); }
}

pid_t dupforkexec(int *fromchild, int *tochild, char **argv) {

    int pi0[2];
    int pi1[2];
    pid_t child;

    if (pipe(pi0) == -1) {
        log_e1("unable to create pipe");
        return -1;
    }
    if (pipe(pi1) == -1) {
        log_e1("unable to create pipe");
        close(pi0[0]);
        close(pi0[1]);
        return -1;
    }

    child = fork();
    if (child == -1) {
        log_e1("unable to fork()");
        close(pi0[0]);
        close(pi0[1]);
        close(pi1[0]);
        close(pi1[1]);
        return -1;
    }

    if (child == 0) {
        close(0);
        if (dup(pi0[0]) != 0) {
            log_e1("unable to dup()");
            _exit(111);
        }
        close(1);
        if (dup(pi1[1]) != 1) {
            log_e1("unable to dup()");
            _exit(111);
        }
        close(pi0[1]);
        close(pi1[0]);
        defaultsignals();
        execvp(*argv, argv);
        log_e2("unable to run ", *argv);
        _exit(111);
    }

    blocking_disable(pi1[0]);
    blocking_disable(pi0[1]);
    *fromchild = pi1[0];
    *tochild = pi0[1];
    close(pi0[0]);
    close(pi1[1]);

    return child;
}

int dupforkexec_wait(pid_t pid, char **argv) {

    pid_t r;
    int status;
    const char *argvname = "";

    if (argv && argv[0]) argvname = argv[0];

    do { r = waitpid(pid, &status, 0); } while (r == -1 && errno == EINTR);
    if (r == -1) {
        log_d3("program '", argvname, "' exited, but waitpid returned -1");
        return 1;
    }

    if (!WIFEXITED(status)) {
        log_e4("program '", argvname, "' killed by signal ",
               log_num(WTERMSIG(status)));
        return 1;
    }
    if (WEXITSTATUS(status) > 0) {
        log_e4("program '", argvname, "' exited with status ",
               log_num(WEXITSTATUS(status)));
        return 1;
    }
    log_d3("program '", argvname, "' exited with status 0");
    return 0;
}
