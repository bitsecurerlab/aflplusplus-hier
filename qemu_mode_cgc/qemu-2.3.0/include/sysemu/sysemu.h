#ifndef SYSEMU_H
#define SYSEMU_H
/* Misc. things related to the system emulator.  */

#include "qemu/typedefs.h"
#include "qemu/option.h"
#include "qemu/queue.h"
#include "qemu/timer.h"
#include "qapi-types.h"
#include "qemu/notify.h"
#include "qemu/main-loop.h"
#include "qemu/bitmap.h"
#include "qom/object.h"

/* vl.c */

extern const char *bios_name;

extern const char *qemu_name;
extern uint8_t qemu_uuid[];
extern bool qemu_uuid_set;
int qemu_uuid_parse(const char *str, uint8_t *uuid);

#define UUID_FMT "%02hhx%02hhx%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
#define UUID_NONE "00000000-0000-0000-0000-000000000000"

bool runstate_check(RunState state);
void runstate_set(RunState new_state);
int runstate_is_running(void);
bool runstate_needs_reset(void);
typedef struct vm_change_state_entry VMChangeStateEntry;
typedef void VMChangeStateHandler(void *opaque, int running, RunState state);

VMChangeStateEntry *qemu_add_vm_change_state_handler(VMChangeStateHandler *cb,
                                                     void *opaque);
void qemu_del_vm_change_state_handler(VMChangeStateEntry *e);
void vm_state_notify(int running, RunState state);

#define VMRESET_SILENT   false
#define VMRESET_REPORT   true

void vm_start(void);
int vm_stop(RunState state);
int vm_stop_force_state(RunState state);

typedef enum WakeupReason {
    /* Always keep QEMU_WAKEUP_REASON_NONE = 0 */
    QEMU_WAKEUP_REASON_NONE = 0,
    QEMU_WAKEUP_REASON_RTC,
    QEMU_WAKEUP_REASON_PMTIMER,
    QEMU_WAKEUP_REASON_OTHER,
} WakeupReason;

void qemu_system_reset_request(void);
void qemu_system_suspend_request(void);
void qemu_register_suspend_notifier(Notifier *notifier);
void qemu_system_wakeup_request(WakeupReason reason);
void qemu_system_wakeup_enable(WakeupReason reason, bool enabled);
void qemu_register_wakeup_notifier(Notifier *notifier);
void qemu_system_shutdown_request(void);
void qemu_system_powerdown_request(void);
void qemu_register_powerdown_notifier(Notifier *notifier);
void qemu_system_debug_request(void);
void qemu_system_vmstop_request(RunState reason);
void qemu_system_vmstop_request_prepare(void);
int qemu_shutdown_requested_get(void);
int qemu_reset_requested_get(void);
void qemu_system_killed(int signal, pid_t pid);
void qemu_devices_reset(void);
void qemu_system_reset(bool report);

void qemu_add_exit_notifier(Notifier *notify);
void qemu_remove_exit_notifier(Notifier *notify);

void qemu_add_machine_init_done_notifier(Notifier *notify);

void hmp_savevm(Monitor *mon, const QDict *qdict);
int load_vmstate(const char *name);
void hmp_delvm(Monitor *mon, const QDict *qdict);
void hmp_info_snapshots(Monitor *mon, const QDict *qdict);

void qemu_announce_self(void);

bool qemu_savevm_state_blocked(Error **errp);
void qemu_savevm_state_begin(QEMUFile *f,
                             const MigrationParams *params);
int qemu_savevm_state_iterate(QEMUFile *f);
void qemu_savevm_state_complete(QEMUFile *f);
void qemu_savevm_state_cancel(void);
uint64_t qemu_savevm_state_pending(QEMUFile *f, uint64_t max_size);
int qemu_loadvm_state(QEMUFile *f);

typedef enum DisplayType
{
    DT_DEFAULT,
    DT_CURSES,
    DT_SDL,
    DT_GTK,
    DT_NOGRAPHIC,
    DT_NONE,
} DisplayType;

extern int autostart;

typedef enum {
    VGA_NONE, VGA_STD, VGA_CIRRUS, VGA_VMWARE, VGA_XENFB, VGA_QXL,
    VGA_TCX, VGA_CG3, VGA_DEVICE
} VGAInterfaceType;

extern int vga_interface_type;
#define xenfb_enabled (vga_interface_type == VGA_XENFB)

extern int graphic_width;
extern int graphic_height;
extern int graphic_depth;
extern DisplayType display_type;
extern int display_opengl;
extern const char *keyboard_layout;
extern int win2k_install_hack;
extern int alt_grab;
extern int ctrl_grab;
extern int smp_cpus;
extern int max_cpus;
extern int cursor_hide;
extern int graphic_rotate;
extern int no_quit;
extern int no_shutdown;
extern int semihosting_enabled;
extern int old_param;
extern int boot_menu;
extern bool boot_strict;
extern uint8_t *boot_splash_filedata;
extern size_t boot_splash_filedata_size;
extern uint8_t qemu_extra_params_fw[2];
extern QEMUClockType rtc_clock;
extern const char *mem_path;
extern int mem_prealloc;

#define MAX_NODES 128

/* The following shall be true for all CPUs:
 *   cpu->cpu_index < max_cpus <= MAX_CPUMASK_BITS
 *
 * Note that cpu->get_arch_id() may be larger than MAX_CPUMASK_BITS.
 */
#define MAX_CPUMASK_BITS 255

#define MAX_OPTION_ROMS 16
typedef struct QEMUOptionRom {
    const char *name;
    int32_t bootindex;
} QEMUOptionRom;
extern QEMUOptionRom option_rom[MAX_OPTION_ROMS];
extern int nb_option_roms;

#define MAX_PROM_ENVS 128
extern const char *prom_envs[MAX_PROM_ENVS];
extern unsigned int nb_prom_envs;

/* generic hotplug */
void hmp_drive_add(Monitor *mon, const QDict *qdict);

/* pcie aer error injection */
void pcie_aer_inject_error_print(Monitor *mon, const QObject *data);
int hmp_pcie_aer_inject_error(Monitor *mon,
                             const QDict *qdict, QObject **ret_data);

/* serial ports */

#define MAX_SERIAL_PORTS 4

extern CharDriverState *serial_hds[MAX_SERIAL_PORTS];

/* parallel ports */

#define MAX_PARALLEL_PORTS 3

extern CharDriverState *parallel_hds[MAX_PARALLEL_PORTS];

void hmp_usb_add(Monitor *mon, const QDict *qdict);
void hmp_usb_del(Monitor *mon, const QDict *qdict);
void hmp_info_usb(Monitor *mon, const QDict *qdict);

void add_boot_device_path(int32_t bootindex, DeviceState *dev,
                          const char *suffix);
char *get_boot_devices_list(size_t *size, bool ignore_suffixes);

DeviceState *get_boot_device(uint32_t position);
void check_boot_index(int32_t bootindex, Error **errp);
void del_boot_device_path(DeviceState *dev, const char *suffix);
void device_add_bootindex_property(Object *obj, int32_t *bootindex,
                                   const char *name, const char *suffix,
                                   DeviceState *dev, Error **errp);
void restore_boot_order(void *opaque);
void validate_bootdevices(const char *devices, Error **errp);

/* handler to set the boot_device order for a specific type of QEMUMachine */
typedef void QEMUBootSetHandler(void *opaque, const char *boot_order,
                                Error **errp);
void qemu_register_boot_set(QEMUBootSetHandler *func, void *opaque);
void qemu_boot_set(const char *boot_order, Error **errp);

QemuOpts *qemu_get_machine_opts(void);

bool defaults_enabled(void);
bool usb_enabled(void);

extern QemuOptsList qemu_legacy_drive_opts;
extern QemuOptsList qemu_common_drive_opts;
extern QemuOptsList qemu_drive_opts;
extern QemuOptsList qemu_chardev_opts;
extern QemuOptsList qemu_device_opts;
extern QemuOptsList qemu_netdev_opts;
extern QemuOptsList qemu_net_opts;
extern QemuOptsList qemu_global_opts;
extern QemuOptsList qemu_mon_opts;

#endif
