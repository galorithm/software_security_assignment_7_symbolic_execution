#include<stdio.h>
#include<sys/types.h>
#include<sys/ptrace.h>

long int ptrace(enum __ptrace_request op, ...)
{
	printf("Dummy bypass ptrace RUNNING!\n");

	// always return success
	return 0;
}

