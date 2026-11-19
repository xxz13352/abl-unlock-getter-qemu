/*
 * main.c - execute the Qualcomm ABL unlock-state getters inside a bare-metal
 *          QEMU guest.
 *
 * Target image: LinuxLoader.efi from an iQOO 13 (PD2408 / SM8750) build
 * 16.1.15.3. All addresses below are image-relative (RVA) and version
 * specific. verify_image() fingerprints the four instructions the experiment
 * depends on and aborts when the loaded image does not match.
 *
 * The experiment:
 *   1. load the PE at PE_BASE and apply its relocations;
 *   2. call the DeviceIsUnlocked / critical-unlock wrappers with both backing
 *      state bytes (temp and devinfo) set to every 0/1 combination;
 *   3. patch the shared `cset w0, ne` to `mov w0, #1` and re-run 0/0.
 *
 * Nothing here touches a device. The harness only proves what the getter
 * returns for a given memory state and a given instruction patch.
 */
#include "console.h"
#include "pe.h"

#define PE_BASE 0x50000000UL

/* 16.1.15.3 LinuxLoader.efi relative addresses */
#define ABL_UNLOCK_WRAPPER   0x1e424UL  /* DeviceIsUnlocked()            */
#define ABL_CRITICAL_WRAPPER 0x1e44cUL  /* critical-unlock wrapper       */
#define ABL_GETTER_BODY      0x1f740UL  /* shared OR + cset body         */
#define ABL_CSET_INSN        0x1f764UL  /* cset w0, ne                   */
#define CANARY_GLOBAL        0x99008UL  /* .data slot, proves data writes */

#define TEMP_UNLOCK          0xbc374UL  /* transient unlock byte         */
#define TEMP_CRITICAL        0xbc375UL  /* transient critical byte       */
#define DEVINFO_UNLOCK       0xbc385UL  /* devinfo-backed unlock byte    */
#define DEVINFO_CRITICAL     0xbc386UL  /* devinfo-backed critical byte  */

/* Fingerprints (little-endian u32) of the instructions used above. */
#define WANT_WRAPPER_INSN    0xd10083ffUL  /* sub sp, sp, #0x20  */
#define WANT_BODY_INSN       0x91002108UL  /* add x8, x8, #8     */
#define WANT_CSET_INSN       0x1a9f07e0UL  /* cset w0, ne        */

#define PATCH_MOV_W0_1       0x52800020UL  /* mov w0, #1         */

extern const uint8_t abl_blob_start[];
extern const uint8_t abl_blob_end[];

typedef unsigned int (*getter_fn)(void);

static unsigned int call_rva(uintptr_t rva)
{
    getter_fn fn = (getter_fn)(PE_BASE + rva);
    return fn();
}

static void set_unlock(unsigned int temp, unsigned int devinfo)
{
    *(volatile uint8_t *)(PE_BASE + TEMP_UNLOCK) = (uint8_t)temp;
    *(volatile uint8_t *)(PE_BASE + DEVINFO_UNLOCK) = (uint8_t)devinfo;
}

static void set_critical(unsigned int temp, unsigned int devinfo)
{
    *(volatile uint8_t *)(PE_BASE + TEMP_CRITICAL) = (uint8_t)temp;
    *(volatile uint8_t *)(PE_BASE + DEVINFO_CRITICAL) = (uint8_t)devinfo;
}

static void run_case(unsigned int temp, unsigned int devinfo)
{
    set_unlock(temp, devinfo);
    kprintf("CASE unlock temp=%u devinfo=%u => %u\n",
            (uint64_t)temp, (uint64_t)devinfo, (uint64_t)call_rva(ABL_UNLOCK_WRAPPER));
    set_critical(temp, devinfo);
    kprintf("CASE critical temp=%u devinfo=%u => %u\n",
            (uint64_t)temp, (uint64_t)devinfo, (uint64_t)call_rva(ABL_CRITICAL_WRAPPER));
}

static void semihost_exit(unsigned int code)
{
    register unsigned long x0 asm("x0") = 0x18; /* SYS_EXIT */
    register unsigned long x1 asm("x1") = code;
    asm volatile("hlt #0xf000" : : "r"(x0), "r"(x1));
}

static int verify_image(void)
{
    static const struct {
        uintptr_t rva;
        uint32_t want;
        const char *name;
    } checks[] = {
        { ABL_UNLOCK_WRAPPER,   WANT_WRAPPER_INSN, "unlock-wrapper"   },
        { ABL_CRITICAL_WRAPPER, WANT_WRAPPER_INSN, "critical-wrapper" },
        { ABL_GETTER_BODY,      WANT_BODY_INSN,    "getter-body"      },
        { ABL_CSET_INSN,        WANT_CSET_INSN,    "cset"             },
    };
    int bad = 0;
    for (unsigned int i = 0; i < sizeof(checks) / sizeof(checks[0]); i++) {
        uint32_t got = *(volatile uint32_t *)(PE_BASE + checks[i].rva);
        int ok = (got == checks[i].want);
        kprintf("VERIFY %s rva=0x%x got=0x%x want=0x%x %s\n",
                checks[i].name, (uint64_t)checks[i].rva, (uint64_t)got,
                (uint64_t)checks[i].want, ok ? "ok" : "MISMATCH");
        bad |= !ok;
    }
    return bad;
}

void kmain(void)
{
    uart_init();
    kprintf("QEMU_ABL_HARNESS start\n");
    kprintf("ABL_BLOB bytes=%u load_base=0x%x wrapper_unlock=0x%x wrapper_critical=0x%x body=0x%x\n",
            (uint64_t)(abl_blob_end - abl_blob_start), (uint64_t)PE_BASE,
            (uint64_t)(PE_BASE + ABL_UNLOCK_WRAPPER),
            (uint64_t)(PE_BASE + ABL_CRITICAL_WRAPPER),
            (uint64_t)(PE_BASE + ABL_GETTER_BODY));

    if (pe_load(abl_blob_start, (size_t)(abl_blob_end - abl_blob_start), PE_BASE) != 0) {
        kprintf("QEMU_ABL_HARNESS load_failed\n");
        kprintf("QEMU_SIM_DONE\n");
        semihost_exit(1);
    }

    if (verify_image() != 0) {
        kprintf("QEMU_ABL_HARNESS image_mismatch\n");
        kprintf("QEMU_SIM_DONE\n");
        semihost_exit(2);
    }

    *(volatile uint64_t *)(PE_BASE + CANARY_GLOBAL) = 0x1122334455667788ULL;
    kprintf("CANARY global=0x%x value=0x%x\n",
            (uint64_t)(PE_BASE + CANARY_GLOBAL),
            *(volatile uint64_t *)(PE_BASE + CANARY_GLOBAL));

    run_case(0, 0);
    run_case(0, 1);
    run_case(1, 0);
    run_case(1, 1);

    uint32_t old = *(volatile uint32_t *)(PE_BASE + ABL_CSET_INSN);
    *(volatile uint32_t *)(PE_BASE + ABL_CSET_INSN) = PATCH_MOV_W0_1;
    flush_icache_all();
    kprintf("PATCH_CODE rva=0x%x old=0x%x new=0x%x\n",
            (uint64_t)ABL_CSET_INSN, (uint64_t)old,
            (uint64_t)*(volatile uint32_t *)(PE_BASE + ABL_CSET_INSN));
    run_case(0, 0);
    run_case(0, 1);

    kprintf("QEMU_SIM_DONE\n");
    semihost_exit(0);
}
