/* util */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/time.h>
#include <stdarg.h>
#include <net/ethernet.h>

#include "rseb.h"

time_t
now(void) {
        struct timeval tp;
        if (gettimeofday(&tp, 0) < 0)
                perror("gettimeofday");
        return tp.tv_sec;
}

void
Log(int level, char *msg, ...) {
	va_list args;

	if (level == LOG_DEBUG && debug < 2)
		return;
	if (level == LOG_INFO && debug < 1)
		return;

	if (use_syslog) {
		va_start(args, msg);
		vsyslog(level, msg, args);
		va_end(args);
	} else {
		char buf[1000];
		va_start(args, msg);
		vsnprintf(buf, sizeof(buf), msg, args);
		va_end(args);
		if (strchr(buf, '\n'))
			fprintf(stderr, "rseb: %s", buf);
		else
			fprintf(stderr, "rseb: %s\n", buf);
	}
}
