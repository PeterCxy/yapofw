#include "loop.h"
#include <strings.h>

// List of all fds that we need to poll
struct pollfd *poll_fds;
size_t poll_fds_len = 0;
empty_slot_t *empty_slots;
size_t empty_slot_num = 0;
// Reverse map from fd number to the index in poll_fds
// Make sure the length of this is always equal to or larger than RLIMIT_NOFILE
// Otherwise it may not be able to house all possible fds
// We use a large reverse map with a dense poll_fds array because a sparse and large
// poll_fds array causes poll() to be much slower than necessary.
size_t *poll_fds_reverse_map;
// Hooks
loop_before_poll_hook_t hooks_before_poll[NUM_HOOKS_MAX];
size_t hooks_before_poll_num = 0;
loop_after_poll_hook_t hooks_after_poll[NUM_HOOKS_MAX];
size_t hooks_after_poll_num = 0;

int event_loop_init(size_t max_fds) {
    // Allocate the maximum possible amount of memory
    // max_fds is normally in the magnitude of thousands
    // or tens of thousands, so the memory consumption
    // should be fine
    poll_fds = malloc(max_fds * sizeof(struct pollfd));
    poll_fds_reverse_map = malloc(max_fds * sizeof(size_t));

    if (poll_fds == NULL || poll_fds_reverse_map == NULL) {
        return -1;
    }

    bzero(poll_fds, max_fds * sizeof(struct pollfd));

    for (int i = 0; i < max_fds; i++) {
        poll_fds[i].fd = -1;
        poll_fds_reverse_map[i] = -1;
    }

    return 0;
}

void event_loop_add_fd(int fd, short events) {
    // Find an empty slot to add the fd
    size_t slot = 0;
    if (empty_slots == NULL) {
        slot = poll_fds_len;
    } else {
        slot = empty_slots->index;
        empty_slot_t *next = empty_slots->next;
        free(empty_slots);
        empty_slots = next;
        empty_slot_num--;
    }

    poll_fds[slot].fd = fd;
    poll_fds[slot].events = events;
    poll_fds[slot].revents = 0;
    poll_fds_reverse_map[fd] = slot;

    if (slot == poll_fds_len) {
        poll_fds_len++;
    }
}

void event_loop_remove_fd(int fd) {
    int idx = poll_fds_reverse_map[fd];
    if (idx == -1 || poll_fds[idx].fd == -1) return; // Already removed
    poll_fds[idx].fd = -1;
    poll_fds[idx].events = 0;
    poll_fds[idx].revents = 0;
    poll_fds_reverse_map[fd] = -1;
    // Add to the head of empty slots
    empty_slot_t *new_slot = malloc(sizeof(empty_slot_t));
    new_slot->index = idx;
    new_slot->next = empty_slots;
    empty_slots = new_slot;
    empty_slot_num++;
}

void event_loop_set_fd_events(int fd, short events) {
    poll_fds[poll_fds_reverse_map[fd]].events |= events;
}

void event_loop_clear_fd_events(int fd, short events) {
    poll_fds[poll_fds_reverse_map[fd]].events &= ~events;
}

int event_loop_fd_revent_is_set(int fd, short event) {
    return poll_fds[poll_fds_reverse_map[fd]].revents & event;
}

// We assume we never register more than NUM_HOOKS_MAX
void event_loop_register_hook_before_poll(loop_before_poll_hook_t hook) {
    hooks_before_poll[hooks_before_poll_num] = hook;
    hooks_before_poll_num++;
}

void event_loop_register_hook_after_poll(loop_after_poll_hook_t hook) {
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