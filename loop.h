#pragma once
#include <poll.h>
#include <stdlib.h>

typedef void (*loop_before_poll_hook_t)();
typedef void (*loop_after_poll_hook_t)();

#define NUM_HOOKS_MAX 10 // Should be larger than the number of protocols supported

int event_loop_init(size_t max_fds);
// Add an fd to the list to be polled
void event_loop_add_fd(int fd, short events);
// Remove an fd from the list to be polled
void event_loop_remove_fd(int fd);
// Add to the events to be listened for the fd
void event_loop_set_fd_events(int fd, short events);
// Remove from the events to be listened for the fd
void event_loop_clear_fd_events(int fd, short events);
// Get revent (events returned by poll) for fd
int event_loop_get_fd_revents(int fd);
// Hooks
void event_loop_register_hook_before_poll(loop_before_poll_hook_t *hook);
void event_loop_register_hook_after_poll(loop_after_poll_hook_t *hook);
void event_loop();