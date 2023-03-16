#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "commands.h"

// Use lxterminal --command= on Pi, gnome-terminal -- on laptop. Would be better to set using an environment variable.
char* term_format = "gnome-terminal -- /proc/%d/exe";
// char* term_format = "lxterminal --command=/proc/%d/exe";
char* fifo_location = "/tmp/shim-fifo";

int dummy_func();
int terminal_func();
int child_func(char** command);

int main(int argc, char** argv) {
    // If no args are provided, act as the dummy for the terminal connection
    if (argc == 1) {
        return dummy_func();
    }

    // Create a FIFO to talk to obtain the terminal dummy's PID
    if (mkfifo(fifo_location, S_IRWXU) == -1) {
        perror("failed to mkfifo() for dummy PID");
        return -2;
    }

    // Spawn the new terminal
    pid_t pid = fork();
    if (pid == -1) {
        perror("failed to call fork() for new terminal");
        return -1;
    }
    else if (pid == 0) {
        return terminal_func();
    }

    // Read the PID from the FIFO and clean up
    FILE* fifo = fopen(fifo_location, "r");
    if (fifo == NULL) {
        perror("failed to fopen() the FIFO");
        return -4;
    }
    pid_t dummy_pid;
    if (fscanf(fifo, "%d", &dummy_pid) != 1) {
        printf("failed to read dummy pid from FIFO\n");
        return -3;
    }
    fclose(fifo);
    if (unlink(fifo_location) == -1) {
        perror("failed to unlink() the FIFO");
        return -5;
    }

    // Spawn the child we want to monitor
    pid = fork();
    if (pid == -1) {
        perror("failed to call fork() for the program to monitor");
        return -1;
    }
    else if (pid == 0) {
        return child_func(&argv[1]);
    }

    // Overwrite the stdout, stdin, and stderr fds so that we write to the new terminal
    char fd_path[256];
    snprintf(fd_path, 256, "/proc/%d/fd/0", dummy_pid);
    freopen(fd_path, "w", stdout);
    snprintf(fd_path, 256, "/proc/%d/fd/1", dummy_pid);
    freopen(fd_path, "r", stdin);
    snprintf(fd_path, 256, "/proc/%d/fd/2", dummy_pid);
    freopen(fd_path, "w", stderr);

    char* input_line = NULL;
    size_t input_len = 0;
    while (1) {
        printf("> ");
        fflush(stdout);

        // Parse input command
        getline(&input_line, &input_len, stdin);
        char cmd_name[256];
        if (sscanf(input_line, "%256s", cmd_name) == 1) {
            if (strcmp(cmd_name, "find") == 0) {
            }
            else if (strcmp(cmd_name, "quit") == 0) {
                break;
            }
            else if (strcmp(cmd_name, "help") == 0) {
                help_cmd(input_line);
            }
            else {
                printf("invalid command - use 'help' to view all available commands\n");
            }
        }
    }

    kill(pid, SIGTERM);
    kill(dummy_pid, SIGTERM);
}

int terminal_func() {
    // Use parent's pid (the initial shim process) since the child doesn't have /proc/PID/exe
    pid_t pid = getppid();
    char command[1024];
    snprintf(command, 1024, term_format, pid);
    return system(command);
}

int dummy_func() {
    printf("shim Command Terminal\n");

    if (access(fifo_location, W_OK) == -1) {
        perror("can't write to the FIFO");
        printf("Usage: shim COMMAND...\n");
        return -1;
    }
    FILE* fifo = fopen(fifo_location, "w");
    if (fifo == NULL) {
        perror("failed to fopen() the FIFO");
        return -2;
    }
    fprintf(fifo, "%d", getpid());
    fclose(fifo);

    return pause();
}

int child_func(char** command) {
    // Initiate ptrace for the parent
    /*
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        perror("failed to initiate ptrace()");
    }
    */

    int ret = execvp(command[0], &command[1]);
    if (ret == -1) {
        perror("failed to execvp() the specified command");
    }
    return ret;
}
