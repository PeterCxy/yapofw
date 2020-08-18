#include "loop.h"
#include <strings.h>

// List of all fds that we need to poll
struct pollfd *poll_fds;
size_t poll_fds_len = 0;
// Hooks
loop_before_poll_hook_t hooks_before_poll[NUM_HOOKS_MAX];
size_t hooks_before_poll_num = 0;
loop_after_poll_hook_t hooks_after_poll[NUM_HOOKS_MAX];
size_t hooks_after_poll_num = 0;

int event_loop_init(size_t max_fds) {
    poll_fds_len = max_fds;
    // Allocate the maximum possible amount of memory
    // max_fds is normally in the magnitude of thousands
    // or tens of thousands, so the memory consumption
    // should be fine
    poll_fds = malloc(max_fds * sizeof(struct pollfd));

    if (poll_fds == NULL) {
        return -1;
    }

    bzero(poll_fds, max_fds * sizeof(struct pollfd));

    for (int i = 0; i < max_fds; i++) {
        poll_fds[i].fd = -1;
    }
}

void event_loop_add_fd(int fd, short events) {
    poll_fds[fd].fd = fd;
    poll_fds[fd].events = events;
    poll_fds[fd].revents = 0;
}

void event_loop_remove_fd(int fd) {
    poll_fds[fd].fd = -1;
    poll_fds[fd].events = 0;
    poll_fds[fd].revents = 0;
}

void event_loop_set_fd_events(int fd, short events) {
    poll_fds[fd].events |= events;
}

void event_loop_clear_fd_events(int fd, short events) {
    poll_fds[fd].events &= ~events;
}

int event_loop_get_fd_revents(int fd) {
    return poll_fds[fd].revents;
}

// We assume we never register more than NUM_HOOKS_MAX
void event_loop_register_hook_before_poll(loop_before_poll_hook_t *hook) {
    hooks_before_poll[hooks_before_poll_num] = hook;
    hooks_before_poll_num++;
}

void event_loop_register_hook_after_poll(loop_after_poll_hook_t *hook) {
    hooks_after_poll[hooks_after_poll_num] = hook;
    hooks_after_poll_num++;
}

void event_loop() {
    while (1) {
        for (int i = 0; i < hooks_before_poll_num; i++) {
            hooks_before_poll[i]();
        }

        int poll_res = poll(poll_fds, poll_fds_len, -1);

        if (poll_res == 0) continue;
        if (poll_res < 0) break; // Error

        for (int i = 0; i < hooks_after_poll_num; i++) {
            hooks_after_poll[i]();
        }
    }
}