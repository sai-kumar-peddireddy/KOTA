#pragma once

struct lifecycle;
struct scalpel;
struct veto;
struct ioctl_observer;

namespace kota::attach {

void attach_kernel_programs(struct lifecycle *lifecycle,
                            struct scalpel   *scalpel,
                            struct veto      *veto,
                            struct ioctl_observer *ioctl_observer);

void teardown_before_object_unload();

} // namespace kota::attach
