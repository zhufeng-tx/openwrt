/*
 * bw-test-bwc — Bandwidth test statistics collector
 *
 * Forks/execs tcp_test or udp_test via forkpty (so the child line-buffers
 * its stdout), parses each output line, and stores samples in a memory-mapped
 * circular buffer file.  Read mode dumps the buffer as JSON in the same
 * [[timestamp, val, ...], ...] format used by luci-bwc.
 *
 * Usage:
 *   bw-test-bwc -s tcp|udp -- <cmd> [args...]   start collector daemon
 *   bw-test-bwc -r tcp|udp                       dump buffer as JSON
 *   bw-test-bwc -k tcp|udp                       stop (kill) daemon
 *   bw-test-bwc -q tcp|udp                       query running status
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <pty.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#define STEP_COUNT  120
#define DB_PATH     "/var/lib/bw-test"

struct bw_entry {
	uint32_t time;      /* Unix timestamp, big-endian */
	uint32_t speed;     /* KB/s, big-endian */
	uint32_t total;     /* UDP RX: total pkts; else 0 */
	uint32_t rx_count;  /* UDP RX: received pkts; else 0 */
	uint32_t lost;      /* UDP RX: lost pkts; else 0 */
};

struct file_map {
	int   fd;
	int   size;
	char *mmap;
};

/* daemon state for signal handler */
static volatile int child_pid = -1;
static char pid_path[256];

static void sigterm_handler(int sig)
{
	(void)sig;
	if (child_pid > 0)
		kill(child_pid, SIGTERM);
	unlink(pid_path);
	_exit(0);
}

static inline uint32_t timeof(const void *entry)
{
	return be32toh(((const struct bw_entry *)entry)->time);
}

static int init_directory(const char *path)
{
	char tmp[256];
	char *p;

	snprintf(tmp, sizeof(tmp), "%s", path);
	for (p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = 0;
			if (mkdir(tmp, 0755) < 0 && errno != EEXIST)
				return -1;
			*p = '/';
		}
	}
	if (mkdir(tmp, 0755) < 0 && errno != EEXIST)
		return -1;
	return 0;
}

static int init_file(const char *path)
{
	struct bw_entry zero = { 0 };
	int fd, i;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	for (i = 0; i < STEP_COUNT; i++) {
		if (write(fd, &zero, sizeof(zero)) < 0)
			break;
	}
	close(fd);
	return 0;
}

static void write_entry(char *map, const struct bw_entry *entry)
{
	if (timeof(entry) > timeof(map + sizeof(struct bw_entry) * (STEP_COUNT - 1))) {
		memmove(map, map + sizeof(struct bw_entry),
		        sizeof(struct bw_entry) * (STEP_COUNT - 1));
		memcpy(map + sizeof(struct bw_entry) * (STEP_COUNT - 1),
		       entry, sizeof(struct bw_entry));
	}
}

static int mmap_file(const char *path, struct file_map *m)
{
	m->fd   = -1;
	m->size = sizeof(struct bw_entry) * STEP_COUNT;
	m->mmap = NULL;

	m->fd = open(path, O_RDONLY);
	if (m->fd < 0)
		return -1;

	m->mmap = mmap(NULL, m->size, PROT_READ, MAP_SHARED, m->fd, 0);
	if (m->mmap == MAP_FAILED) {
		close(m->fd);
		m->fd = -1;
		return -1;
	}
	return 0;
}

static void umap_file(struct file_map *m)
{
	if (m->mmap && m->mmap != MAP_FAILED)
		munmap(m->mmap, m->size);
	if (m->fd >= 0)
		close(m->fd);
}

static int write_pid(const char *path)
{
	FILE *f = fopen(path, "w");
	if (!f)
		return -1;
	fprintf(f, "%d\n", getpid());
	fclose(f);
	return 0;
}

static int read_pid(const char *path)
{
	FILE *f;
	int pid = -1;
	f = fopen(path, "r");
	if (!f)
		return -1;
	fscanf(f, "%d", &pid);
	fclose(f);
	return pid;
}

static int parse_tcp_line(const char *line, struct bw_entry *entry)
{
	unsigned int speed;
	if (sscanf(line, "TCP trans speed: %uKB/s", &speed) == 1) {
		entry->time     = htobe32((uint32_t)time(NULL));
		entry->speed    = htobe32(speed);
		entry->total    = 0;
		entry->rx_count = 0;
		entry->lost     = 0;
		return 1;
	}
	return 0;
}

static int parse_udp_line(const char *line, struct bw_entry *entry)
{
	unsigned int speed, total, rx_count, lost, loss_pct;

	if (sscanf(line, "TX speed: %u KByte/s", &speed) == 1) {
		entry->time     = htobe32((uint32_t)time(NULL));
		entry->speed    = htobe32(speed);
		entry->total    = 0;
		entry->rx_count = 0;
		entry->lost     = 0;
		return 1;
	}

	if (sscanf(line, "RX speed: %u KByte/s (total:%u, rx:%u, lost:%u, %u%%)",
	           &speed, &total, &rx_count, &lost, &loss_pct) == 5) {
		entry->time     = htobe32((uint32_t)time(NULL));
		entry->speed    = htobe32(speed);
		entry->total    = htobe32(total);
		entry->rx_count = htobe32(rx_count);
		entry->lost     = htobe32(lost);
		return 1;
	}

	return 0;
}

typedef int (*parse_fn_t)(const char *, struct bw_entry *);

static int run_start(int is_udp, char **cmd_argv)
{
	char data_path[256];
	struct sigaction sa;
	parse_fn_t parse_fn;
	int master_fd;
	char line_buf[512];
	char read_buf[512];
	int line_len = 0;
	char c;
	char *data_map = NULL;
	int data_size = sizeof(struct bw_entry) * STEP_COUNT;
	int old_pid;
	struct winsize ws = { .ws_row = 24, .ws_col = 80 };

	snprintf(data_path, sizeof(data_path), DB_PATH "/%s", is_udp ? "udp" : "tcp");
	snprintf(pid_path,  sizeof(pid_path),  DB_PATH "/%s.pid", is_udp ? "udp" : "tcp");
	parse_fn = is_udp ? parse_udp_line : parse_tcp_line;

	/* kill any previously running daemon of the same type */
	old_pid = read_pid(pid_path);
	if (old_pid > 0) {
		kill(old_pid, SIGTERM);
		usleep(300000);
	}

	if (init_directory(DB_PATH) < 0) {
		fprintf(stderr, "bw-test-bwc: cannot create %s: %s\n",
		        DB_PATH, strerror(errno));
		return 1;
	}
	if (init_file(data_path) < 0) {
		fprintf(stderr, "bw-test-bwc: cannot init %s: %s\n",
		        data_path, strerror(errno));
		return 1;
	}

	/* fork: parent exits immediately so the caller (rpcd) returns quickly */
	switch (fork()) {
	case -1:
		perror("fork");
		return 1;
	case 0:
		break; /* child becomes the daemon */
	default:
		return 0; /* parent: success */
	}

	/* --- daemon child --- */
	setsid();

	/* redirect standard fds to /dev/null */
	{
		int devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			if (devnull > STDERR_FILENO)
				close(devnull);
		}
	}

	/* SIGTERM handler for clean shutdown */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigterm_handler;
	sa.sa_flags   = SA_RESTART;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	/* SIG_DFL: the explicit waitpid below reaps the child */
	signal(SIGCHLD, SIG_DFL);

	if (write_pid(pid_path) < 0)
		_exit(1);

	/*
	 * Launch the test tool via forkpty so the child thinks it has a
	 * terminal and keeps its stdout line-buffered.
	 */
	child_pid = forkpty(&master_fd, NULL, NULL, &ws);
	if (child_pid < 0) {
		unlink(pid_path);
		_exit(1);
	}

	if (child_pid == 0) {
		/* grandchild: exec the test tool */
		execvp(cmd_argv[0], cmd_argv);
		_exit(127);
	}

	/* map the data file once for the daemon's lifetime */
	{
		int dfd = open(data_path, O_RDWR);
		if (dfd >= 0) {
			data_map = mmap(NULL, data_size, PROT_READ | PROT_WRITE,
			                MAP_SHARED, dfd, 0);
			close(dfd);
			if (data_map == MAP_FAILED)
				data_map = NULL;
		}
	}

	/* daemon: read child output and parse into circular buffer */
	while (1) {
		ssize_t n = read(master_fd, read_buf, sizeof(read_buf));
		if (n <= 0)
			break; /* child exited (EIO on PTY EOF) or error */

		for (ssize_t j = 0; j < n; j++) {
			c = read_buf[j];
			if (c == '\r')
				continue;
			if (c == '\n' || line_len >= (int)sizeof(line_buf) - 1) {
				line_buf[line_len] = '\0';
				line_len = 0;

				struct bw_entry entry;
				if (parse_fn(line_buf, &entry) && data_map)
					write_entry(data_map, &entry);
			} else {
				line_buf[line_len++] = c;
			}
		}
	}

	close(master_fd);
	if (data_map)
		munmap(data_map, data_size);
	if (child_pid > 0) {
		kill(child_pid, SIGTERM);
		waitpid(child_pid, NULL, 0);
	}
	unlink(pid_path);
	_exit(0);
}

static int run_read(int is_udp)
{
	char data_path[256];
	struct file_map m;
	const struct bw_entry *e;
	int i, first = 1;

	snprintf(data_path, sizeof(data_path), DB_PATH "/%s", is_udp ? "udp" : "tcp");

	if (mmap_file(data_path, &m) < 0)
		return 0; /* no data yet — output nothing, not an error */

	for (i = 0; i < STEP_COUNT; i++) {
		e = (const struct bw_entry *)(m.mmap + i * sizeof(struct bw_entry));
		if (!e->time)
			continue;
		if (!first)
			printf(",\n");
		printf("[ %u, %u, %u, %u, %u ]",
		       be32toh(e->time),
		       be32toh(e->speed),
		       be32toh(e->total),
		       be32toh(e->rx_count),
		       be32toh(e->lost));
		first = 0;
	}
	if (!first)
		putchar('\n');

	umap_file(&m);
	return 0;
}

static int run_stop(int is_udp)
{
	char data_path[256];
	int pid;

	snprintf(pid_path,  sizeof(pid_path),  DB_PATH "/%s.pid", is_udp ? "udp" : "tcp");
	snprintf(data_path, sizeof(data_path), DB_PATH "/%s",     is_udp ? "udp" : "tcp");

	pid = read_pid(pid_path);
	if (pid > 0) {
		kill(pid, SIGTERM);
		usleep(500000);
		if (kill(pid, 0) == 0)
			kill(pid, SIGKILL);
	}
	unlink(pid_path);
	unlink(data_path);
	return 0;
}

static int run_status(int is_udp)
{
	int pid, running;

	snprintf(pid_path, sizeof(pid_path), DB_PATH "/%s.pid", is_udp ? "udp" : "tcp");

	pid     = read_pid(pid_path);
	running = (pid > 0 && kill(pid, 0) == 0);

	printf("{\"running\":%s}\n", running ? "true" : "false");
	return 0;
}

int main(int argc, char *argv[])
{
	int opt;
	char mode = 0;
	int is_udp = 0;
	int cmd_start = -1;
	int i;

	while ((opt = getopt(argc, argv, "srkq")) > -1) {
		switch (opt) {
		case 's': mode = 's'; break;
		case 'r': mode = 'r'; break;
		case 'k': mode = 'k'; break;
		case 'q': mode = 'q'; break;
		default:
			fprintf(stderr, "Usage: bw-test-bwc -s|-r|-k|-q tcp|udp [-- cmd args]\n");
			return 1;
		}
	}

	if (!mode || optind >= argc) {
		fprintf(stderr, "Usage: bw-test-bwc -s|-r|-k|-q tcp|udp [-- cmd args]\n");
		return 1;
	}

	if (strcmp(argv[optind], "tcp") == 0) {
		is_udp = 0;
	} else if (strcmp(argv[optind], "udp") == 0) {
		is_udp = 1;
	} else {
		fprintf(stderr, "bw-test-bwc: unknown protocol '%s' (use tcp or udp)\n",
		        argv[optind]);
		return 1;
	}

	if (mode == 's') {
		for (i = optind + 1; i < argc; i++) {
			if (strcmp(argv[i], "--") == 0) {
				cmd_start = i + 1;
				break;
			}
		}
		if (cmd_start < 0 || cmd_start >= argc) {
			fprintf(stderr, "bw-test-bwc -s: missing -- <command>\n");
			return 1;
		}
		return run_start(is_udp, argv + cmd_start);
	}

	switch (mode) {
	case 'r': return run_read(is_udp);
	case 'k': return run_stop(is_udp);
	case 'q': return run_status(is_udp);
	}

	return 1;
}
