/*
 * QEMU emulation of an Intel IOMMU (VT-d)
 *   (DMA Remapping device)
 *
 * Copyright (C) 2013 Knut Omang, Oracle <knut.omang@oracle.com>
 * Copyright (C) 2014 Le Tan, <tamlokveer@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "hw/sysbus.h"
#include "exec/address-spaces.h"
#include "intel_iommu_internal.h"

/*#define DEBUG_INTEL_IOMMU*/
#ifdef DEBUG_INTEL_IOMMU
enum {
    DEBUG_GENERAL, DEBUG_CSR, DEBUG_INV, DEBUG_MMU, DEBUG_FLOG,
    DEBUG_CACHE,
};
#define VTD_DBGBIT(x)   (1 << DEBUG_##x)
static int vtd_dbgflags = VTD_DBGBIT(GENERAL) | VTD_DBGBIT(CSR);

#define VTD_DPRINTF(what, fmt, ...) do { \
    if (vtd_dbgflags & VTD_DBGBIT(what)) { \
        fprintf(stderr, "(vtd)%s: " fmt "\n", __func__, \
                ## __VA_ARGS__); } \
    } while (0)
#else
#define VTD_DPRINTF(what, fmt, ...) do {} while (0)
#endif

static void vtd_define_quad(IntelIOMMUState *s, hwaddr addr, uint64_t val,
                            uint64_t wmask, uint64_t w1cmask)
{
    stq_le_p(&s->csr[addr], val);
    stq_le_p(&s->wmask[addr], wmask);
    stq_le_p(&s->w1cmask[addr], w1cmask);
}

static void vtd_define_quad_wo(IntelIOMMUState *s, hwaddr addr, uint64_t mask)
{
    stq_le_p(&s->womask[addr], mask);
}

static void vtd_define_long(IntelIOMMUState *s, hwaddr addr, uint32_t val,
                            uint32_t wmask, uint32_t w1cmask)
{
    stl_le_p(&s->csr[addr], val);
    stl_le_p(&s->wmask[addr], wmask);
    stl_le_p(&s->w1cmask[addr], w1cmask);
}

static void vtd_define_long_wo(IntelIOMMUState *s, hwaddr addr, uint32_t mask)
{
    stl_le_p(&s->womask[addr], mask);
}

/* "External" get/set operations */
static void vtd_set_quad(IntelIOMMUState *s, hwaddr addr, uint64_t val)
{
    uint64_t oldval = ldq_le_p(&s->csr[addr]);
    uint64_t wmask = ldq_le_p(&s->wmask[addr]);
    uint64_t w1cmask = ldq_le_p(&s->w1cmask[addr]);
    stq_le_p(&s->csr[addr],
             ((oldval & ~wmask) | (val & wmask)) & ~(w1cmask & val));
}

static void vtd_set_long(IntelIOMMUState *s, hwaddr addr, uint32_t val)
{
    uint32_t oldval = ldl_le_p(&s->csr[addr]);
    uint32_t wmask = ldl_le_p(&s->wmask[addr]);
    uint32_t w1cmask = ldl_le_p(&s->w1cmask[addr]);
    stl_le_p(&s->csr[addr],
             ((oldval & ~wmask) | (val & wmask)) & ~(w1cmask & val));
}

static uint64_t vtd_get_quad(IntelIOMMUState *s, hwaddr addr)
{
    uint64_t val = ldq_le_p(&s->csr[addr]);
    uint64_t womask = ldq_le_p(&s->womask[addr]);
    return val & ~womask;
}

static uint32_t vtd_get_long(IntelIOMMUState *s, hwaddr addr)
{
    uint32_t val = ldl_le_p(&s->csr[addr]);
    uint32_t womask = ldl_le_p(&s->womask[addr]);
    return val & ~womask;
}

/* "Internal" get/set operations */
static uint64_t vtd_get_quad_raw(IntelIOMMUState *s, hwaddr addr)
{
    return ldq_le_p(&s->csr[addr]);
}

static uint32_t vtd_get_long_raw(IntelIOMMUState *s, hwaddr addr)
{
    return ldl_le_p(&s->csr[addr]);
}

static void vtd_set_quad_raw(IntelIOMMUState *s, hwaddr addr, uint64_t val)
{
    stq_le_p(&s->csr[addr], val);
}

static uint32_t vtd_set_clear_mask_long(IntelIOMMUState *s, hwaddr addr,
                                        uint32_t clear, uint32_t mask)
{
    uint32_t new_val = (ldl_le_p(&s->csr[addr]) & ~clear) | mask;
    stl_le_p(&s->csr[addr], new_val);
    return new_val;
}

static uint64_t vtd_set_clear_mask_quad(IntelIOMMUState *s, hwaddr addr,
                                        uint64_t clear, uint64_t mask)
{
    uint64_t new_val = (ldq_le_p(&s->csr[addr]) & ~clear) | mask;
    stq_le_p(&s->csr[addr], new_val);
    return new_val;
}

/* GHashTable functions */
static gboolean vtd_uint64_equal(gconstpointer v1, gconstpointer v2)
{
    return *((const uint64_t *)v1) == *((const uint64_t *)v2);
}

static guint vtd_uint64_hash(gconstpointer v)
{
    return (guint)*(const uint64_t *)v;
}

static gboolean vtd_hash_remove_by_domain(gpointer key, gpointer value,
                                          gpointer user_data)
{
    VTDIOTLBEntry *entry = (VTDIOTLBEntry *)value;
    uint16_t domain_id = *(uint16_t *)user_data;
    return entry->domain_id == domain_id;
}

static gboolean vtd_hash_remove_by_page(gpointer key, gpointer value,
                                        gpointer user_data)
{
    VTDIOTLBEntry *entry = (VTDIOTLBEntry *)value;
    VTDIOTLBPageInvInfo *info = (VTDIOTLBPageInvInfo *)user_data;
    uint64_t gfn = info->gfn & info->mask;
    return (entry->domain_id == info->domain_id) &&
            ((entry->gfn & info->mask) == gfn);
}

/* Reset all the gen of VTDAddressSpace to zero and set the gen of
 * IntelIOMMUState to 1.
 */
static void vtd_reset_context_cache(IntelIOMMUState *s)
{
    VTDAddressSpace **pvtd_as;
    VTDAddressSpace *vtd_as;
    uint32_t bus_it;
    uint32_t devfn_it;

    VTD_DPRINTF(CACHE, "global context_cache_gen=1");
    for (bus_it = 0; bus_it < VTD_PCI_BUS_MAX; ++bus_it) {
        pvtd_as = s->address_spaces[bus_it];
        if (!pvtd_as) {
            continue;
        }
        for (devfn_it = 0; devfn_it < VTD_PCI_DEVFN_MAX; ++devfn_it) {
            vtd_as = pvtd_as[devfn_it];
            if (!vtd_as) {
                continue;
            }
            vtd_as->context_cache_entry.context_cache_gen = 0;
        }
    }
    s->context_cache_gen = 1;
}

static void vtd_reset_iotlb(IntelIOMMUState *s)
{
    assert(s->iotlb);
    g_hash_table_remove_all(s->iotlb);
}

static VTDIOTLBEntry *vtd_lookup_iotlb(IntelIOMMUState *s, uint16_t source_id,
                                       hwaddr addr)
{
    uint64_t key;

    key = (addr >> VTD_PAGE_SHIFT_4K) |
           ((uint64_t)(source_id) << VTD_IOTLB_SID_SHIFT);
    return g_hash_table_lookup(s->iotlb, &key);

}

static void vtd_update_iotlb(IntelIOMMUState *s, uint16_t source_id,
                             uint16_t domain_id, hwaddr addr, uint64_t slpte,
                             bool read_flags, bool write_flags)
{
    VTDIOTLBEntry *entry = g_malloc(sizeof(*entry));
    uint64_t *key = g_malloc(sizeof(*key));
    uint64_t gfn = addr >> VTD_PAGE_SHIFT_4K;

    VTD_DPRINTF(CACHE, "update iotlb sid 0x%"PRIx16 " gpa 0x%"PRIx64
                " slpte 0x%"PRIx64 " did 0x%"PRIx16, source_id, addr, slpte,
                domain_id);
    if (g_hash_table_size(s->iotlb) >= VTD_IOTLB_MAX_SIZE) {
        VTD_DPRINTF(CACHE, "iotlb exceeds size limit, forced to reset");
        vtd_reset_iotlb(s);
    }

    entry->gfn = gfn;
    entry->domain_id = domain_id;
    entry->slpte = slpte;
    entry->read_flags = read_flags;
    entry->write_flags = write_flags;
    *key = gfn | ((uint64_t)(source_id) << VTD_IOTLB_SID_SHIFT);
    g_hash_table_replace(s->iotlb, key, entry);
}

/* Given the reg addr of both the message data and address, generate an
 * interrupt via MSI.
 */
static void vtd_generate_interrupt(IntelIOMMUState *s, hwaddr mesg_addr_reg,
                                   hwaddr mesg_data_reg)
{
    hwaddr addr;
    uint32_t data;

    assert(mesg_data_reg < DMAR_REG_SIZE);
    assert(mesg_addr_reg < DMAR_REG_SIZE);

    addr = vtd_get_long_raw(s, mesg_addr_reg);
    data = vtd_get_long_raw(s, mesg_data_reg);

    VTD_DPRINTF(FLOG, "msi: addr 0x%"PRIx64 " data 0x%"PRIx32, addr, data);
    stl_le_phys(&address_space_memory, addr, data);
}

/* Generate a fault event to software via MSI if conditions are met.
 * Notice that the value of FSTS_REG being passed to it should be the one
 * before any update.
 */
static void vtd_generate_fault_event(IntelIOMMUState *s, uint32_t pre_fsts)
{
    if (pre_fsts & VTD_FSTS_PPF || pre_fsts & VTD_FSTS_PFO ||
        pre_fsts & VTD_FSTS_IQE) {
        VTD_DPRINTF(FLOG, "there are previous interrupt conditions "
                    "to be serviced by software, fault event is not generated "
                    "(FSTS_REG 0x%"PRIx32 ")", pre_fsts);
        return;
    }
    vtd_set_clear_mask_long(s, DMAR_FECTL_REG, 0, VTD_FECTL_IP);
    if (vtd_get_long_raw(s, DMAR_FECTL_REG) & VTD_FECTL_IM) {
        VTD_DPRINTF(FLOG, "Interrupt Mask set, fault event is not generated");
    } else {
        vtd_generate_interrupt(s, DMAR_FEADDR_REG, DMAR_FEDATA_REG);
        vtd_set_clear_mask_long(s, DMAR_FECTL_REG, VTD_FECTL_IP, 0);
    }
}

/* Check if the Fault (F) field of the Fault Recording Register referenced by
 * @index is Set.
 */
static bool vtd_is_frcd_set(IntelIOMMUState *s, uint16_t index)
{
    /* Each reg is 128-bit */
    hwaddr addr = DMAR_FRCD_REG_OFFSET + (((uint64_t)index) << 4);
    addr += 8; /* Access the high 64-bit half */

    assert(index < DMAR_FRCD_REG_NR);

    return vtd_get_quad_raw(s, addr) & VTD_FRCD_F;
}

/* Update the PPF field of Fault Status Register.
 * Should be called whenever change the F field of any fault recording
 * registers.
 */
static void vtd_update_fsts_ppf(IntelIOMMUState *s)
{
    uint32_t i;
    uint32_t ppf_mask = 0;

    for (i = 0; i < DMAR_FRCD_REG_NR; i++) {
        if (vtd_is_frcd_set(s, i)) {
            ppf_mask = VTD_FSTS_PPF;
            break;
        }
    }
    vtd_set_clear_mask_long(s, DMAR_FSTS_REG, VTD_FSTS_PPF, ppf_mask);
    VTD_DPRINTF(FLOG, "set PPF of FSTS_REG to %d", ppf_mask ? 1 : 0);
}

static void vtd_set_frcd_and_update_ppf(IntelIOMMUState *s, uint16_t index)
{
    /* Each reg is 128-bit */
    hwaddr addr = DMAR_FRCD_REG_OFFSET + (((uint64_t)index) << 4);
    addr += 8; /* Access the high 64-bit half */

    assert(index < DMAR_FRCD_REG_NR);

    vtd_set_clear_mask_quad(s, addr, 0, VTD_FRCD_F);
    vtd_update_fsts_ppf(s);
}

/* Must not update F field now, should be done later */
static void vtd_record_frcd(IntelIOMMUState *s, uint16_t index,
                            uint16_t source_id, hwaddr addr,
                            VTDFaultReason fault, bool is_write)
{
    uint64_t hi = 0, lo;
    hwaddr frcd_reg_addr = DMAR_FRCD_REG_OFFSET + (((uint64_t)index) << 4);

    assert(index < DMAR_FRCD_REG_NR);

    lo = VTD_FRCD_FI(addr);
    hi = VTD_FRCD_SID(source_id) | VTD_FRCD_FR(fault);
    if (!is_write) {
        hi |= VTD_FRCD_T;
    }
    vtd_set_quad_raw(s, frcd_reg_addr, lo);
    vtd_set_quad_raw(s, frcd_reg_addr + 8, hi);
    VTD_DPRINTF(FLOG, "record to FRCD_REG #%"PRIu16 ": hi 0x%"PRIx64
                ", lo 0x%"PRIx64, index, hi, lo);
}

/* Try to collapse multiple pending faults from the same requester */
static bool vtd_try_collapse_fault(IntelIOMMUState *s, uint16_t source_id)
{
    uint32_t i;
    uint64_t frcd_reg;
    hwaddr addr = DMAR_FRCD_REG_OFFSET + 8; /* The high 64-bit half */

    for (i = 0; i < DMAR_FRCD_REG_NR; i++) {
        frcd_reg = vtd_get_quad_raw(s, addr);
        VTD_DPRINTF(FLOG, "frcd_reg #%d 0x%"PRIx64, i, frcd_reg);
        if ((frcd_reg & VTD_FRCD_F) &&
            ((frcd_reg & VTD_FRCD_SID_MASK) == source_id)) {
            return true;
        }
        addr += 16; /* 128-bit for each */
    }
    return false;
}

/* Log and report an DMAR (address translation) fault to software */
static void vtd_report_dmar_fault(IntelIOMMUState *s, uint16_t source_id,
                                  hwaddr addr, VTDFaultReason fault,
                                  bool is_write)
{
    uint32_t fsts_reg = vtd_get_long_raw(s, DMAR_FSTS_REG);

    assert(fault < VTD_FR_MAX);

    if (fault == VTD_FR_RESERVED_ERR) {
        /* This is not a normal fault reason case. Drop it. */
        return;
    }
    VTD_DPRINTF(FLOG, "sid 0x%"PRIx16 ", fault %d, addr 0x%"PRIx64
                ", is_write %d", source_id, fault, addr, is_write);
    if (fsts_reg & VTD_FSTS_PFO) {
        VTD_DPRINTF(FLOG, "new fault is not recorded due to "
                    "Primary Fault Overflow");
        return;
    }
    if (vtd_try_collapse_fault(s, source_id)) {
        VTD_DPRINTF(FLOG, "new fault is not recorded due to "
                    "compression of faults");
        return;
    }
    if (vtd_is_frcd_set(s, s->next_frcd_reg)) {
        VTD_DPRINTF(FLOG, "Primary Fault Overflow and "
                    "new fault is not recorded, set PFO field");
        vtd_set_clear_mask_long(s, DMAR_FSTS_REG, 0, VTD_FSTS_PFO);
        return;
    }

    vtd_record_frcd(s, s->next_frcd_reg, source_id, addr, fault, is_write);

    if (fsts_reg & VTD_FSTS_PPF) {
        VTD_DPRINTF(FLOG, "there are pending faults already, "
                    "fault event is not generated");
        vtd_set_frcd_and_update_ppf(s, s->next_frcd_reg);
        s->next_frcd_reg++;
        if (s->next_frcd_reg == DMAR_FRCD_REG_NR) {
            s->next_frcd_reg = 0;
        }
    } else {
        vtd_set_clear_mask_long(s, DMAR_FSTS_REG, VTD_FSTS_FRI_MASK,
                                VTD_FSTS_FRI(s->next_frcd_reg));
        vtd_set_frcd_and_update_ppf(s, s->next_frcd_reg); /* Will set PPF */
        s->next_frcd_reg++;
        if (s->next_frcd_reg == DMAR_FRCD_REG_NR) {
            s->next_frcd_reg = 0;
        }
        /* This case actually cause the PPF to be Set.
         * So generate fault event (interrupt).
         */
         vtd_generate_fault_event(s, fsts_reg);
    }
}

/* Handle Invalidation Queue Errors of queued invalidation interface error
 * conditions.
 */
static void vtd_handle_inv_queue_error(IntelIOMMUState *s)
{
    uint32_t fsts_reg = vtd_get_long_raw(s, DMAR_FSTS_REG);

    vtd_set_clear_mask_long(s, DMAR_FSTS_REG, 0, VTD_FSTS_IQE);
    vtd_generate_fault_event(s, fsts_reg);
}

/* Set the IWC field and try to generate an invalidation completion interrupt */
static void vtd_generate_completion_event(IntelIOMMUState *s)
{
    VTD_DPRINTF(INV, "completes an invalidation wait command with "
                "Interrupt Flag");
    if (vtd_get_long_raw(s, DMAR_ICS_REG) & VTD_ICS_IWC) {
        VTD_DPRINTF(INV, "there is a previous interrupt condition to be "
                    "serviced by software, "
                    "new invalidation event is not generated");
        return;
    }
    vtd_set_clear_mask_long(s, DMAR_ICS_REG, 0, VTD_ICS_IWC);
    vtd_set_clear_mask_long(s, DMAR_IECTL_REG, 0, VTD_IECTL_IP);
    if (vtd_get_long_raw(s, DMAR_IECTL_REG) & VTD_IECTL_IM) {
        VTD_DPRINTF(INV, "IM filed in IECTL_REG is set, new invalidation "
                    "event is not generated");
        return;
    } else {
        /* Generate the interrupt event */
        vtd_generate_interrupt(s, DMAR_IEADDR_REG, DMAR_IEDATA_REG);
        vtd_set_clear_mask_long(s, DMAR_IECTL_REG, VTD_IECTL_IP, 0);
    }
}

static inline bool vtd_root_entry_present(VTDRootEntry *root)
{
    return root->val & VTD_ROOT_ENTRY_P;
}

static int vtd_get_root_entry(IntelIOMMUState *s, uint8_t index,
                              VTDRootEntry *re)
{
    dma_addr_t addr;

    addr = s->root + index * sizeof(*re);
    if (dma_memory_read(&address_space_memory, addr, re, sizeof(*re))) {
        VTD_DPRINTF(GENERAL, "error: fail to access root-entry at 0x%"PRIx64
                    " + %"PRIu8, s->root, index);
        re->val = 0;
        return -VTD_FR_ROOT_TABLE_INV;
    }
    re->val = le64_to_cpu(re->val);
    return 0;
}

static inline bool vtd_context_entry_present(VTDContextEntry *context)
{
    return context->lo & VTD_CONTEXT_ENTRY_P;
}

static int vtd_get_context_entry_from_root(VTDRootEntry *root, uint8_t index,
                                           VTDContextEntry *ce)
{
    dma_addr_t addr;

    if (!vtd_root_entry_present(root)) {
        VTD_DPRINTF(GENERAL, "error: root-entry is not present");
        return -VTD_FR_ROOT_ENTRY_P;
    }
    addr = (root->val & VTD_ROOT_ENTRY_CTP) + index * sizeof(*ce);
    if (dma_memory_read(&address_space_memory, addr, ce, sizeof(*ce))) {
        VTD_DPRINTF(GENERAL, "error: fail to access context-entry at 0x%"PRIx64
                    " + %"PRIu8,
                    (uint64_t)(root->val & VTD_ROOT_ENTRY_CTP), index);
        return -VTD_FR_CONTEXT_TABLE_INV;
    }
    ce->lo = le64_to_cpu(ce->lo);
    ce->hi = le64_to_cpu(ce->hi);
    return 0;
}

static inline dma_addr_t vtd_get_slpt_base_from_context(VTDContextEntry *ce)
{
    return ce->lo & VTD_CONTEXT_ENTRY_SLPTPTR;
}

/* The shift of an addr for a certain level of paging structure */
static inline uint32_t vtd_slpt_level_shift(uint32_t level)
{
    return VTD_PAGE_SHIFT_4K + (level - 1) * VTD_SL_LEVEL_BITS;
}

static inline uint64_t vtd_get_slpte_addr(uint64_t slpte)
{
    return slpte & VTD_SL_PT_BASE_ADDR_MASK;
}

/* Whether the pte indicates the address of the page frame */
static inline bool vtd_is_last_slpte(uint64_t slpte, uint32_t level)
{
    return level == VTD_SL_PT_LEVEL || (slpte & VTD_SL_PT_PAGE_SIZE_MASK);
}

/* Get the content of a spte located in @base_addr[@index] */
static uint64_t vtd_get_slpte(dma_addr_t base_addr, uint32_t index)
{
    uint64_t slpte;

    assert(index < VTD_SL_PT_ENTRY_NR);

    if (dma_memory_read(&address_space_memory,
                        base_addr + index * sizeof(slpte), &slpte,
                        sizeof(slpte))) {
        slpte = (uint64_t)-1;
        return slpte;
    }
    slpte = le64_to_cpu(slpte);
    return slpte;
}

/* Given a gpa and the level of paging structure, return the offset of current
 * level.
 */
static inline uint32_t vtd_gpa_level_offset(uint64_t gpa, uint32_t level)
{
    return (gpa >> vtd_slpt_level_shift(level)) &
            ((1ULL << VTD_SL_LEVEL_BITS) - 1);
}

/* Check Capability Register to see if the @level of page-table is supported */
static inline bool vtd_is_level_supported(IntelIOMMUState *s, uint32_t level)
{
    return VTD_CAP_SAGAW_MASK & s->cap &
           (1ULL << (level - 2 + VTD_CAP_SAGAW_SHIFT));
}

/* Get the page-table level that hardware should use for the second-level
 * page-table walk from the Address Width field of context-entry.
 */
static inline uint32_t vtd_get_level_from_context_entry(VTDContextEntry *ce)
{
    return 2 + (ce->hi & VTD_CONTEXT_ENTRY_AW);
}

static inline uint32_t vtd_get_agaw_from_context_entry(VTDContextEntry *ce)
{
    return 30 + (ce->hi & VTD_CONTEXT_ENTRY_AW) * 9;
}

static const uint64_t vtd_paging_entry_rsvd_field[] = {
    [0] = ~0ULL,
    /* For not large page */
    [1] = 0x800ULL | ~(VTD_HAW_MASK | VTD_SL_IGN_COM),
    [2] = 0x800ULL | ~(VTD_HAW_MASK | VTD_SL_IGN_COM),
    [3] = 0x800ULL | ~(VTD_HAW_MASK | VTD_SL_IGN_COM),
    [4] = 0x880ULL | ~(VTD_HAW_MASK | VTD_SL_IGN_COM),
    /* For large page */
    [5] = 0x800ULL | ~(VTD_HAW_MASK | VTD_SL_IGN_COM),
    [6] = 0x1ff800ULL | ~(VTD_HAW_MASK | VTD_SL_IGN_COM),
    [7] = 0x3ffff800ULL | ~(VTD_HAW_MASK | VTD_SL_IGN_COM),
    [8] = 0x880ULL | ~(VTD_HAW_MASK | VTD_SL_IGN_COM),
};

static bool vtd_slpte_nonzero_rsvd(uint64_t slpte, uint32_t level)
{
    if (slpte & VTD_SL_PT_PAGE_SIZE_MASK) {
        /* Maybe large page */
        return slpte & vtd_paging_entry_rsvd_field[level + 4];
    } else {
        return slpte & vtd_paging_entry_rsvd_field[level];
    }
}

/* Given the @gpa, get relevant @slptep. @slpte_level will be the last level
 * of the translation, can be used for deciding the size of large page.
 */
static int vtd_gpa_to_slpte(VTDContextEntry *ce, uint64_t gpa, bool is_write,
                            uint64_t *slptep, uint32_t *slpte_level,
                            bool *reads, bool *writes)
{
    dma_addr_t addr = vtd_get_slpt_base_from_context(ce);
    uint32_t level = vtd_get_level_from_context_entry(ce);
    uint32_t offset;
    uint64_t slpte;
    uint32_t ce_agaw = vtd_get_agaw_from_context_entry(ce);
    uint64_t access_right_check;

    /* Check if @gpa is above 2^X-1, where X is the minimum of MGAW in CAP_REG
     * and AW in context-entry.
     */
    if (gpa & ~((1ULL << MIN(ce_agaw, VTD_MGAW)) - 1)) {
        VTD_DPRINTF(GENERAL, "error: gpa 0x%"PRIx64 " exceeds limits", gpa);
        return -VTD_FR_ADDR_BEYOND_MGAW;
    }

    /* FIXME: what is the Atomics request here? */
    access_right_check = is_write ? VTD_SL_W : VTD_SL_R;

    while (true) {
        offset = vtd_gpa_level_offset(gpa, level);
        slpte = vtd_get_slpte(addr, offset);

        if (slpte == (uint64_t)-1) {
            VTD_DPRINTF(GENERAL, "error: fail to access second-level paging "
                        "entry at level %"PRIu32 " for gpa 0x%"PRIx64,
                        level, gpa);
            if (level == vtd_get_level_from_context_entry(ce)) {
                /* Invalid programming of context-entry */
                return -VTD_FR_CONTEXT_ENTRY_INV;
            } else {
                return -VTD_FR_PAGING_ENTRY_INV;
            }
        }
        *reads = (*reads) && (slpte & VTD_SL_R);
        *writes = (*writes) && (slpte & VTD_SL_W);
        if (!(slpte & access_right_check)) {
            VTD_DPRINTF(GENERAL, "error: lack of %s permission for "
                        "gpa 0x%"PRIx64 " slpte 0x%"PRIx64,
                        (is_write ? "write" : "read"), gpa, slpte);
            return is_write ? -VTD_FR_WRITE : -VTD_FR_READ;
        }
        if (vtd_slpte_nonzero_rsvd(slpte, level)) {
            VTD_DPRINTF(GENERAL, "error: non-zero reserved field in second "
                        "level paging entry level %"PRIu32 " slpte 0x%"PRIx64,
                        level, slpte);
            return -VTD_FR_PAGING_ENTRY_RSVD;
        }

        if (vtd_is_last_slpte(slpte, level)) {
            *slptep = slpte;
            *slpte_level = level;
            return 0;
        }
        addr = vtd_get_slpte_addr(slpte);
        level--;
    }
}

/* Map a device to its corresponding domain (context-entry) */
static int vtd_dev_to_context_entry(IntelIOMMUState *s, uint8_t bus_num,
                                    uint8_t devfn, VTDContextEntry *ce)
{
    VTDRootEntry re;
    int ret_fr;

    ret_fr = vtd_get_root_entry(s, bus_num, &re);
    if (ret_fr) {
        return ret_fr;
    }

    if (!vtd_root_entry_present(&re)) {
        VTD_DPRINTF(GENERAL, "error: root-entry #%"PRIu8 " is not present",
                    bus_num);
        return -VTD_FR_ROOT_ENTRY_P;
    } else if (re.rsvd || (re.val & VTD_ROOT_ENTRY_RSVD)) {
        VTD_DPRINTF(GENERAL, "error: non-zero reserved field in root-entry "
                    "hi 0x%"PRIx64 " lo 0x%"PRIx64, re.rsvd, re.val);
        return -VTD_FR_ROOT_ENTRY_RSVD;
    }

    ret_fr = vtd_get_context_entry_from_root(&re, devfn, ce);
    if (ret_fr) {
        return ret_fr;
    }

    if (!vtd_context_entry_present(ce)) {
        VTD_DPRINTF(GENERAL,
                    "error: context-entry #%"PRIu8 "(bus #%"PRIu8 ") "
                    "is not present", devfn, bus_num);
        return -VTD_FR_CONTEXT_ENTRY_P;
    } else if ((ce->hi & VTD_CONTEXT_ENTRY_RSVD_HI) ||
               (ce->lo & VTD_CONTEXT_ENTRY_RSVD_LO)) {
        VTD_DPRINTF(GENERAL,
                    "error: non-zero reserved field in context-entry "
                    "hi 0x%"PRIx64 " lo 0x%"PRIx64, ce->hi, ce->lo);
        return -VTD_FR_CONTEXT_ENTRY_RSVD;
    }
    /* Check if the programming of context-entry is valid */
    if (!vtd_is_level_supported(s, vtd_get_level_from_context_entry(ce))) {
        VTD_DPRINTF(GENERAL, "error: unsupported Address Width value in "
                    "context-entry hi 0x%"PRIx64 " lo 0x%"PRIx64,
                    ce->hi, ce->lo);
        return -VTD_FR_CONTEXT_ENTRY_INV;
    } else if (ce->lo & VTD_CONTEXT_ENTRY_TT) {
        VTD_DPRINTF(GENERAL, "error: unsupported Translation Type in "
                    "context-entry hi 0x%"PRIx64 " lo 0x%"PRIx64,
                    ce->hi, ce->lo);
        return -VTD_FR_CONTEXT_ENTRY_INV;
    }
    return 0;
}

static inline uint16_t vtd_make_source_id(uint8_t bus_num, uint8_t devfn)
{
    return ((bus_num & 0xffUL) << 8) | (devfn & 0xffUL);
}

static const bool vtd_qualified_faults[] = {
    [VTD_FR_RESERVED] = false,
    [VTD_FR_ROOT_ENTRY_P] = false,
    [VTD_FR_CONTEXT_ENTRY_P] = true,
    [VTD_FR_CONTEXT_ENTRY_INV] = true,
    [VTD_FR_ADDR_BEYOND_MGAW] = true,
    [VTD_FR_WRITE] = true,
    [VTD_FR_READ] = true,
    [VTD_FR_PAGING_ENTRY_INV] = true,
    [VTD_FR_ROOT_TABLE_INV] = false,
    [VTD_FR_CONTEXT_TABLE_INV] = false,
    [VTD_FR_ROOT_ENTRY_RSVD] = false,
    [VTD_FR_PAGING_ENTRY_RSVD] = true,
    [VTD_FR_CONTEXT_ENTRY_TT] = true,
    [VTD_FR_RESERVED_ERR] = false,
    [VTD_FR_MAX] = false,
};

/* To see if a fault condition is "qualified", which is reported to software
 * only if the FPD field in the context-entry used to process the faulting
 * request is 0.
 */
static inline bool vtd_is_qualified_fault(VTDFaultReason fault)
{
    return vtd_qualified_faults[fault];
}

static inline bool vtd_is_interrupt_addr(hwaddr addr)
{
    return VTD_INTERRUPT_ADDR_FIRST <= addr && addr <= VTD_INTERRUPT_ADDR_LAST;
}

/* Map dev to context-entry then do a paging-structures walk to do a iommu
 * translation.
 *
 * Called from RCU critical section.
 *
 * @bus_num: The bus number
 * @devfn: The devfn, which is the  combined of device and function number
 * @is_write: The access is a write operation
 * @entry: IOMMUTLBEntry that contain the addr to be translated and result
 */
static void vtd_do_iommu_translate(VTDAddressSpace *vtd_as, uint8_t bus_num,
                                   uint8_t devfn, hwaddr addr, bool is_write,
                                   IOMMUTLBEntry *entry)
{
    IntelIOMMUState *s = vtd_as->iommu_state;
    VTDContextEntry ce;
    VTDContextCacheEntry *cc_entry = &vtd_as->context_cache_entry;
    uint64_t slpte;
    uint32_t level;
    uint16_t source_id = vtd_make_source_id(bus_num, devfn);
    int ret_fr;
    bool is_fpd_set = false;
    bool reads = true;
    bool writes = true;
    VTDIOTLBEntry *iotlb_entry;

    /* Check if the request is in interrupt address range */
    if (vtd_is_interrupt_addr(addr)) {
        if (is_write) {
            /* FIXME: since we don't know the length of the access here, we
             * treat Non-DWORD length write requests without PASID as
             * interrupt requests, too. Withoud interrupt remapping support,
             * we just use 1:1 mapping.
             */
            VTD_DPRINTF(MMU, "write request to interrupt address "
                        "gpa 0x%"PRIx64, addr);
            entry->iova = addr & VTD_PAGE_MASK_4K;
            entry->translated_addr = addr & VTD_PAGE_MASK_4K;
            entry->addr_mask = ~VTD_PAGE_MASK_4K;
            entry->perm = IOMMU_WO;
            return;
        } else {
            VTD_DPRINTF(GENERAL, "error: read request from interrupt address "
                        "gpa 0x%"PRIx64, addr);
            vtd_report_dmar_fault(s, source_id, addr, VTD_FR_READ, is_write);
            return;
        }
    }
    /* Try to fetch slpte form IOTLB */
    iotlb_entry = vtd_lookup_iotlb(s, source_id, addr);
    if (iotlb_entry) {
        VTD_DPRINTF(CACHE, "hit iotlb sid 0x%"PRIx16 " gpa 0x%"PRIx64
                    " slpte 0x%"PRIx64 " did 0x%"PRIx16, source_id, addr,
                    iotlb_entry->slpte, iotlb_entry->domain_id);
        slpte = iotlb_entry->slpte;
        reads = iotlb_entry->read_flags;
        writes = iotlb_entry->write_flags;
        goto out;
    }
    /* Try to fetch context-entry from cache first */
    if (cc_entry->context_cache_gen == s->context_cache_gen) {
        VTD_DPRINTF(CACHE, "hit context-cache bus %d devfn %d "
                    "(hi %"PRIx64 " lo %"PRIx64 " gen %"PRIu32 ")",
                    bus_num, devfn, cc_entry->context_entry.hi,
                    cc_entry->context_entry.lo, cc_entry->context_cache_gen);
        ce = cc_entry->context_entry;
        is_fpd_set = ce.lo & VTD_CONTEXT_ENTRY_FPD;
    } else {
        ret_fr = vtd_dev_to_context_entry(s, bus_num, devfn, &ce);
        is_fpd_set = ce.lo & VTD_CONTEXT_ENTRY_FPD;
        if (ret_fr) {
            ret_fr = -ret_fr;
            if (is_fpd_set && vtd_is_qualified_fault(ret_fr)) {
                VTD_DPRINTF(FLOG, "fault processing is disabled for DMA "
                            "requests through this context-entry "
                            "(with FPD Set)");
            } else {
                vtd_report_dmar_fault(s, source_id, addr, ret_fr, is_write);
            }
            return;
        }
        /* Update context-cache */
        VTD_DPRINTF(CACHE, "update context-cache bus %d devfn %d "
                    "(hi %"PRIx64 " lo %"PRIx64 " gen %"PRIu32 "->%"PRIu32 ")",
                    bus_num, devfn, ce.hi, ce.lo,
                    cc_entry->context_cache_gen, s->context_cache_gen);
        cc_entry->context_entry = ce;
        cc_entry->context_cache_gen = s->context_cache_gen;
    }

    ret_fr = vtd_gpa_to_slpte(&ce, addr, is_write, &slpte, &level,
                              &reads, &writes);
    if (ret_fr) {
        ret_fr = -ret_fr;
        if (is_fpd_set && vtd_is_qualified_fault(ret_fr)) {
            VTD_DPRINTF(FLOG, "fault processing is disabled for DMA requests "
                        "through this context-entry (with FPD Set)");
        } else {
            vtd_report_dmar_fault(s, source_id, addr, ret_fr, is_write);
        }
        return;
    }

    vtd_update_iotlb(s, source_id, VTD_CONTEXT_ENTRY_DID(ce.hi), addr, slpte,
                     reads, writes);
out:
    entry->iova = addr & VTD_PAGE_MASK_4K;
    entry->translated_addr = vtd_get_slpte_addr(slpte) & VTD_PAGE_MASK_4K;
    entry->addr_mask = ~VTD_PAGE_MASK_4K;
    entry->perm = (writes ? 2 : 0) + (reads ? 1 : 0);
}

static void vtd_root_table_setup(IntelIOMMUState *s)
{
    s->root = vtd_get_quad_raw(s, DMAR_RTADDR_REG);
    s->root_extended = s->root & VTD_RTADDR_RTT;
    s->root &= VTD_RTADDR_ADDR_MASK;

    VTD_DPRINTF(CSR, "root_table addr 0x%"PRIx64 " %s", s->root,
                (s->root_extended ? "(extended)" : ""));
}

static void vtd_context_global_invalidate(IntelIOMMUState *s)
{
    s->context_cache_gen++;
    if (s->context_cache_gen == VTD_CONTEXT_CACHE_GEN_MAX) {
        vtd_reset_context_cache(s);
    }
}

/* Do a context-cache device-selective invalidation.
 * @func_mask: FM field after shifting
 */
static void vtd_context_device_invalidate(IntelIOMMUState *s,
                                          uint16_t source_id,
                                          uint16_t func_mask)
{
    uint16_t mask;
    VTDAddressSpace **pvtd_as;
    VTDAddressSpace *vtd_as;
    uint16_t devfn;
    uint16_t devfn_it;

    switch (func_mask & 3) {
    case 0:
        mask = 0;   /* No bits in the SID field masked */
        break;
    case 1:
        mask = 4;   /* Mask bit 2 in the SID field */
        break;
    case 2:
        mask = 6;   /* Mask bit 2:1 in the SID field */
        break;
    case 3:
        mask = 7;   /* Mask bit 2:0 in the SID field */
        break;
    }
    VTD_DPRINTF(INV, "device-selective invalidation source 0x%"PRIx16
                    " mask %"PRIu16, source_id, mask);
    pvtd_as = s->address_spaces[VTD_SID_TO_BUS(source_id)];
    if (pvtd_as) {
        devfn = VTD_SID_TO_DEVFN(source_id);
        for (devfn_it = 0; devfn_it < VTD_PCI_DEVFN_MAX; ++devfn_it) {
            vtd_as = pvtd_as[devfn_it];
            if (vtd_as && ((devfn_it & mask) == (devfn & mask))) {
                VTD_DPRINTF(INV, "invalidate context-cahce of devfn 0x%"PRIx16,
                            devfn_it);
                vtd_as->context_cache_entry.context_cache_gen = 0;
            }
        }
    }
}

/* Context-cache invalidation
 * Returns the Context Actual Invalidation Granularity.
 * @val: the content of the CCMD_REG
 */
static uint64_t vtd_context_cache_invalidate(IntelIOMMUState *s, uint64_t val)
{
    uint64_t caig;
    uint64_t type = val & VTD_CCMD_CIRG_MASK;

    switch (type) {
    case VTD_CCMD_DOMAIN_INVL:
        VTD_DPRINTF(INV, "domain-selective invalidation domain 0x%"PRIx16,
                    (uint16_t)VTD_CCMD_DID(val));
        /* Fall through */
    case VTD_CCMD_GLOBAL_INVL:
        VTD_DPRINTF(INV, "global invalidation");
        caig = VTD_CCMD_GLOBAL_INVL_A;
        vtd_context_global_invalidate(s);
        break;

    case VTD_CCMD_DEVICE_INVL:
        caig = VTD_CCMD_DEVICE_INVL_A;
        vtd_context_device_invalidate(s, VTD_CCMD_SID(val), VTD_CCMD_FM(val));
        break;

    default:
        VTD_DPRINTF(GENERAL, "error: invalid granularity");
        caig = 0;
    }
    return caig;
}

static void vtd_iotlb_global_invalidate(IntelIOMMUState *s)
{
    vtd_reset_iotlb(s);
}

static void vtd_iotlb_domain_invalidate(IntelIOMMUState *s, uint16_t domain_id)
{
    g_hash_table_foreach_remove(s->iotlb, vtd_hash_remove_by_domain,
                                &domain_id);
}

static void vtd_iotlb_page_invalidate(IntelIOMMUState *s, uint16_t domain_id,
                                      hwaddr addr, uint8_t am)
{
    VTDIOTLBPageInvInfo info;

    assert(am <= VTD_MAMV);
    info.domain_id = domain_id;
    info.gfn = addr >> VTD_PAGE_SHIFT_4K;
    info.mask = ~((1 << am) - 1);
    g_hash_table_foreach_remove(s->iotlb, vtd_hash_remove_by_page, &info);
}

/* Flush IOTLB
 * Returns the IOTLB Actual Invalidation Granularity.
 * @val: the content of the IOTLB_REG
 */
static uint64_t vtd_iotlb_flush(IntelIOMMUState *s, uint64_t val)
{
    uint64_t iaig;
    uint64_t type = val & VTD_TLB_FLUSH_GRANU_MASK;
    uint16_t domain_id;
    hwaddr addr;
    uint8_t am;

    switch (type) {
    case VTD_TLB_GLOBAL_FLUSH:
        VTD_DPRINTF(INV, "global invalidation");
        iaig = VTD_TLB_GLOBAL_FLUSH_A;
        vtd_iotlb_global_invalidate(s);
        break;

    case VTD_TLB_DSI_FLUSH:
        domain_id = VTD_TLB_DID(val);
        VTD_DPRINTF(INV, "domain-selective invalidation domain 0x%"PRIx16,
                    domain_id);
        iaig = VTD_TLB_DSI_FLUSH_A;
        vtd_iotlb_domain_invalidate(s, domain_id);
        break;

    case VTD_TLB_PSI_FLUSH:
        domain_id = VTD_TLB_DID(val);
        addr = vtd_get_quad_raw(s, DMAR_IVA_REG);
        am = VTD_IVA_AM(addr);
        addr = VTD_IVA_ADDR(addr);
        VTD_DPRINTF(INV, "page-selective invalidation domain 0x%"PRIx16
                    " addr 0x%"PRIx64 " mask %"PRIu8, domain_id, addr, am);
        if (am > VTD_MAMV) {
            VTD_DPRINTF(GENERAL, "error: supported max address mask value is "
                        "%"PRIu8, (uint8_t)VTD_MAMV);
            iaig = 0;
            break;
        }
        iaig = VTD_TLB_PSI_FLUSH_A;
        vtd_iotlb_page_invalidate(s, domain_id, addr, am);
        break;

    default:
        VTD_DPRINTF(GENERAL, "error: invalid granularity");
        iaig = 0;
    }
    return iaig;
}

static inline bool vtd_queued_inv_enable_check(IntelIOMMUState *s)
{
    return s->iq_tail == 0;
}

static inline bool vtd_queued_inv_disable_check(IntelIOMMUState *s)
{
    return s->qi_enabled && (s->iq_tail == s->iq_head) &&
           (s->iq_last_desc_type == VTD_INV_DESC_WAIT);
}

static void vtd_handle_gcmd_qie(IntelIOMMUState *s, bool en)
{
    uint64_t iqa_val = vtd_get_quad_raw(s, DMAR_IQA_REG);

    VTD_DPRINTF(INV, "Queued Invalidation Enable %s", (en ? "on" : "off"));
    if (en) {
        if (vtd_queued_inv_enable_check(s)) {
            s->iq = iqa_val & VTD_IQA_IQA_MASK;
            /* 2^(x+8) entries */
            s->iq_size = 1UL << ((iqa_val & VTD_IQA_QS) + 8);
            s->qi_enabled = true;
            VTD_DPRINTF(INV, "DMAR_IQA_REG 0x%"PRIx64, iqa_val);
            VTD_DPRINTF(INV, "Invalidation Queue addr 0x%"PRIx64 " size %d",
                        s->iq, s->iq_size);
            /* Ok - report back to driver */
            vtd_set_clear_mask_long(s, DMAR_GSTS_REG, 0, VTD_GSTS_QIES);
        } else {
            VTD_DPRINTF(GENERAL, "error: can't enable Queued Invalidation: "
                        "tail %"PRIu16, s->iq_tail);
        }
    } else {
        if (vtd_queued_inv_disable_check(s)) {
            /* disable Queued Invalidation */
            vtd_set_quad_raw(s, DMAR_IQH_REG, 0);
            s->iq_head = 0;
            s->qi_enabled = false;
            /* Ok - report back to driver */
            vtd_set_clear_mask_long(s, DMAR_GSTS_REG, VTD_GSTS_QIES, 0);
        } else {
            VTD_DPRINTF(GENERAL, "error: can't disable Queued Invalidation: "
                        "head %"PRIu16 ", tail %"PRIu16
                        ", last_descriptor %"PRIu8,
                        s->iq_head, s->iq_tail, s->iq_last_desc_type);
        }
    }
}

/* Set Root Table Pointer */
static void vtd_handle_gcmd_srtp(IntelIOMMUState *s)
{
    VTD_DPRINTF(CSR, "set Root Table Pointer");

    vtd_root_table_setup(s);
    /* Ok - report back to driver */
    vtd_set_clear_mask_long(s, DMAR_GSTS_REG, 0, VTD_GSTS_RTPS);
}

/* Handle Translation Enable/Disable */
static void vtd_handle_gcmd_te(IntelIOMMUState *s, bool en)
{
    VTD_DPRINTF(CSR, "Translation Enable %s", (en ? "on" : "off"));

    if (en) {
        s->dmar_enabled = true;
        /* Ok - report back to driver */
        vtd_set_clear_mask_long(s, DMAR_GSTS_REG, 0, VTD_GSTS_TES);
    } else {
        s->dmar_enabled = false;

        /* Clear the index of Fault Recording Register */
        s->next_frcd_reg = 0;
        /* Ok - report back to driver */
        vtd_set_clear_mask_long(s, DMAR_GSTS_REG, VTD_GSTS_TES, 0);
    }
}

/* Handle write to Global Command Register */
static void vtd_handle_gcmd_write(IntelIOMMUState *s)
{
    uint32_t status = vtd_get_long_raw(s, DMAR_GSTS_REG);
    uint32_t val = vtd_get_long_raw(s, DMAR_GCMD_REG);
    uint32_t changed = status ^ val;

    VTD_DPRINTF(CSR, "value 0x%"PRIx32 " status 0x%"PRIx32, val, status);
    if (changed & VTD_GCMD_TE) {
        /* Translation enable/disable */
        vtd_handle_gcmd_te(s, val & VTD_GCMD_TE);
    }
    if (val & VTD_GCMD_SRTP) {
        /* Set/update the root-table pointer */
        vtd_handle_gcmd_srtp(s);
    }
    if (changed & VTD_GCMD_QIE) {
        /* Queued Invalidation Enable */
        vtd_handle_gcmd_qie(s, val & VTD_GCMD_QIE);
    }
}

/* Handle write to Context Command Register */
static void vtd_handle_ccmd_write(IntelIOMMUState *s)
{
    uint64_t ret;
    uint64_t val = vtd_get_quad_raw(s, DMAR_CCMD_REG);

    /* Context-cache invalidation request */
    if (val & VTD_CCMD_ICC) {
        if (s->qi_enabled) {
            VTD_DPRINTF(GENERAL, "error: Queued Invalidation enabled, "
                        "should not use register-based invalidation");
            return;
        }
        ret = vtd_context_cache_invalidate(s, val);
        /* Invalidation completed. Change something to show */
        vtd_set_clear_mask_quad(s, DMAR_CCMD_REG, VTD_CCMD_ICC, 0ULL);
        ret = vtd_set_clear_mask_quad(s, DMAR_CCMD_REG, VTD_CCMD_CAIG_MASK,
                                      ret);
        VTD_DPRINTF(INV, "CCMD_REG write-back val: 0x%"PRIx64, ret);
    }
}

/* Handle write to IOTLB Invalidation Register */
static void vtd_handle_iotlb_write(IntelIOMMUState *s)
{
    uint64_t ret;
    uint64_t val = vtd_get_quad_raw(s, DMAR_IOTLB_REG);

    /* IOTLB invalidation request */
    if (val & VTD_TLB_IVT) {
        if (s->qi_enabled) {
            VTD_DPRINTF(GENERAL, "error: Queued Invalidation enabled, "
                        "should not use register-based invalidation");
            return;
        }
        ret = vtd_iotlb_flush(s, val);
        /* Invalidation completed. Change something to show */
        vtd_set_clear_mask_quad(s, DMAR_IOTLB_REG, VTD_TLB_IVT, 0ULL);
        ret = vtd_set_clear_mask_quad(s, DMAR_IOTLB_REG,
                                      VTD_TLB_FLUSH_GRANU_MASK_A, ret);
        VTD_DPRINTF(INV, "IOTLB_REG write-back val: 0x%"PRIx64, ret);
    }
}

/* Fetch an Invalidation Descriptor from the Invalidation Queue */
static bool vtd_get_inv_desc(dma_addr_t base_addr, uint32_t offset,
                             VTDInvDesc *inv_desc)
{
    dma_addr_t addr = base_addr + offset * sizeof(*inv_desc);
    if (dma_memory_read(&address_space_memory, addr, inv_desc,
        sizeof(*inv_desc))) {
        VTD_DPRINTF(GENERAL, "error: fail to fetch Invalidation Descriptor "
                    "base_addr 0x%"PRIx64 " offset %"PRIu32, base_addr, offset);
        inv_desc->lo = 0;
        inv_desc->hi = 0;

        return false;
    }
    inv_desc->lo = le64_to_cpu(inv_desc->lo);
    inv_desc->hi = le64_to_cpu(inv_desc->hi);
    return true;
}

static bool vtd_process_wait_desc(IntelIOMMUState *s, VTDInvDesc *inv_desc)
{
    if ((inv_desc->hi & VTD_INV_DESC_WAIT_RSVD_HI) ||
        (inv_desc->lo & VTD_INV_DESC_WAIT_RSVD_LO)) {
        VTD_DPRINTF(GENERAL, "error: non-zero reserved field in Invalidation "
                    "Wait Descriptor hi 0x%"PRIx64 " lo 0x%"PRIx64,
                    inv_desc->hi, inv_desc->lo);
        return false;
    }
    if (inv_desc->lo & VTD_INV_DESC_WAIT_SW) {
        /* Status Write */
        uint32_t status_data = (uint32_t)(inv_desc->lo >>
                               VTD_INV_DESC_WAIT_DATA_SHIFT);

        assert(!(inv_desc->lo & VTD_INV_DESC_WAIT_IF));

        /* FIXME: need to be masked with HAW? */
        dma_addr_t status_addr = inv_desc->hi;
        VTD_DPRINTF(INV, "status data 0x%x, status addr 0x%"PRIx64,
                    status_data, status_addr);
        status_data = cpu_to_le32(status_data);
        if (dma_memory_write(&address_space_memory, status_addr, &status_data,
                             sizeof(status_data))) {
            VTD_DPRINTF(GENERAL, "error: fail to perform a coherent write");
            return false;
        }
    } else if (inv_desc->lo & VTD_INV_DESC_WAIT_IF) {
        /* Interrupt flag */
        VTD_DPRINTF(INV, "Invalidation Wait Descriptor interrupt completion");
        vtd_generate_completion_event(s);
    } else {
        VTD_DPRINTF(GENERAL, "error: invalid Invalidation Wait Descriptor: "
                    "hi 0x%"PRIx64 " lo 0x%"PRIx64, inv_desc->hi, inv_desc->lo);
        return false;
    }
    return true;
}

static bool vtd_process_context_cache_desc(IntelIOMMUState *s,
                                           VTDInvDesc *inv_desc)
{
    if ((inv_desc->lo & VTD_INV_DESC_CC_RSVD) || inv_desc->hi) {
        VTD_DPRINTF(GENERAL, "error: non-zero reserved field in Context-cache "
                    "Invalidate Descriptor");
        return false;
    }
    switch (inv_desc->lo & VTD_INV_DESC_CC_G) {
    case VTD_INV_DESC_CC_DOMAIN:
        VTD_DPRINTF(INV, "domain-selective invalidation domain 0x%"PRIx16,
                    (uint16_t)VTD_INV_DESC_CC_DID(inv_desc->lo));
        /* Fall through */
    case VTD_INV_DESC_CC_GLOBAL:
        VTD_DPRINTF(INV, "global invalidation");
        vtd_context_global_invalidate(s);
        break;

    case VTD_INV_DESC_CC_DEVICE:
        vtd_context_device_invalidate(s, VTD_INV_DESC_CC_SID(inv_desc->lo),
                                      VTD_INV_DESC_CC_FM(inv_desc->lo));
        break;

    default:
        VTD_DPRINTF(GENERAL, "error: invalid granularity in Context-cache "
                    "Invalidate Descriptor hi 0x%"PRIx64  " lo 0x%"PRIx64,
                    inv_desc->hi, inv_desc->lo);
        return false;
    }
    return true;
}

static bool vtd_process_iotlb_desc(IntelIOMMUState *s, VTDInvDesc *inv_desc)
{
    uint16_t domain_id;
    uint8_t am;
    hwaddr addr;

    if ((inv_desc->lo & VTD_INV_DESC_IOTLB_RSVD_LO) ||
        (inv_desc->hi & VTD_INV_DESC_IOTLB_RSVD_HI)) {
        VTD_DPRINTF(GENERAL, "error: non-zero reserved field in IOTLB "
                    "Invalidate Descriptor hi 0x%"PRIx64 " lo 0x%"PRIx64,
                    inv_desc->hi, inv_desc->lo);
        return false;
    }

    switch (inv_desc->lo & VTD_INV_DESC_IOTLB_G) {
    case VTD_INV_DESC_IOTLB_GLOBAL:
        VTD_DPRINTF(INV, "global invalidation");
        vtd_iotlb_global_invalidate(s);
        break;

    case VTD_INV_DESC_IOTLB_DOMAIN:
        domain_id = VTD_INV_DESC_IOTLB_DID(inv_desc->lo);
        VTD_DPRINTF(INV, "domain-selective invalidation domain 0x%"PRIx16,
                    domain_id);
        vtd_iotlb_domain_invalidate(s, domain_id);
        break;

    case VTD_INV_DESC_IOTLB_PAGE:
        domain_id = VTD_INV_DESC_IOTLB_DID(inv_desc->lo);
        addr = VTD_INV_DESC_IOTLB_ADDR(inv_desc->hi);
        am = VTD_INV_DESC_IOTLB_AM(inv_desc->hi);
        VTD_DPRINTF(INV, "page-selective invalidation domain 0x%"PRIx16
                    " addr 0x%"PRIx64 " mask %"PRIu8, domain_id, addr, am);
        if (am > VTD_MAMV) {
            VTD_DPRINTF(GENERAL, "error: supported max address mask value is "
                        "%"PRIu8, (uint8_t)VTD_MAMV);
            return false;
        }
        vtd_iotlb_page_invalidate(s, domain_id, addr, am);
        break;

    default:
        VTD_DPRINTF(GENERAL, "error: invalid granularity in IOTLB Invalidate "
                    "Descriptor hi 0x%"PRIx64 " lo 0x%"PRIx64,
                    inv_desc->hi, inv_desc->lo);
        return false;
    }
    return true;
}

static bool vtd_process_inv_desc(IntelIOMMUState *s)
{
    VTDInvDesc inv_desc;
    uint8_t desc_type;

    VTD_DPRINTF(INV, "iq head %"PRIu16, s->iq_head);
    if (!vtd_get_inv_desc(s->iq, s->iq_head, &inv_desc)) {
        s->iq_last_desc_type = VTD_INV_DESC_NONE;
        return false;
    }
    desc_type = inv_desc.lo & VTD_INV_DESC_TYPE;
    /* FIXME: should update at first or at last? */
    s->iq_last_desc_type = desc_type;

    switch (desc_type) {
    case VTD_INV_DESC_CC:
        VTD_DPRINTF(INV, "Context-cache Invalidate Descriptor hi 0x%"PRIx64
                    " lo 0x%"PRIx64, inv_desc.hi, inv_desc.lo);
        if (!vtd_process_context_cache_desc(s, &inv_desc)) {
            return false;
        }
        break;

    case VTD_INV_DESC_IOTLB:
        VTD_DPRINTF(INV, "IOTLB Invalidate Descriptor hi 0x%"PRIx64
                    " lo 0x%"PRIx64, inv_desc.hi, inv_desc.lo);
        if (!vtd_process_iotlb_desc(s, &inv_desc)) {
            return false;
        }
        break;

    case VTD_INV_DESC_WAIT:
        VTD_DPRINTF(INV, "Invalidation Wait Descriptor hi 0x%"PRIx64
                    " lo 0x%"PRIx64, inv_desc.hi, inv_desc.lo);
        if (!vtd_process_wait_desc(s, &inv_desc)) {
            return false;
        }
        break;

    default:
        VTD_DPRINTF(GENERAL, "error: unkonw Invalidation Descriptor type "
                    "hi 0x%"PRIx64 " lo 0x%"PRIx64 " type %"PRIu8,
                    inv_desc.hi, inv_desc.lo, desc_type);
        return false;
    }
    s->iq_head++;
    if (s->iq_head == s->iq_size) {
        s->iq_head = 0;
    }
    return true;
}

/* Try to fetch and process more Invalidation Descriptors */
static void vtd_fetch_inv_desc(IntelIOMMUState *s)
{
    VTD_DPRINTF(INV, "fetch Invalidation Descriptors");
    if (s->iq_tail >= s->iq_size) {
        /* Detects an invalid Tail pointer */
        VTD_DPRINTF(GENERAL, "error: iq_tail is %"PRIu16
                    " while iq_size is %"PRIu16, s->iq_tail, s->iq_size);
        vtd_handle_inv_queue_error(s);
        return;
    }
    while (s->iq_head != s->iq_tail) {
        if (!vtd_process_inv_desc(s)) {
            /* Invalidation Queue Errors */
            vtd_handle_inv_queue_error(s);
            break;
        }
        /* Must update the IQH_REG in time */
        vtd_set_quad_raw(s, DMAR_IQH_REG,
                         (((uint64_t)(s->iq_head)) << VTD_IQH_QH_SHIFT) &
                         VTD_IQH_QH_MASK);
    }
}

/* Handle write to Invalidation Queue Tail Register */
static void vtd_handle_iqt_write(IntelIOMMUState *s)
{
    uint64_t val = vtd_get_quad_raw(s, DMAR_IQT_REG);

    s->iq_tail = VTD_IQT_QT(val);
    VTD_DPRINTF(INV, "set iq tail %"PRIu16, s->iq_tail);
    if (s->qi_enabled && !(vtd_get_long_raw(s, DMAR_FSTS_REG) & VTD_FSTS_IQE)) {
        /* Process Invalidation Queue here */
        vtd_fetch_inv_desc(s);
    }
}

static void vtd_handle_fsts_write(IntelIOMMUState *s)
{
    uint32_t fsts_reg = vtd_get_long_raw(s, DMAR_FSTS_REG);
    uint32_t fectl_reg = vtd_get_long_raw(s, DMAR_FECTL_REG);
    uint32_t status_fields = VTD_FSTS_PFO | VTD_FSTS_PPF | VTD_FSTS_IQE;

    if ((fectl_reg & VTD_FECTL_IP) && !(fsts_reg & status_fields)) {
        vtd_set_clear_mask_long(s, DMAR_FECTL_REG, VTD_FECTL_IP, 0);
        VTD_DPRINTF(FLOG, "all pending interrupt conditions serviced, clear "
                    "IP field of FECTL_REG");
    }
    /* FIXME: when IQE is Clear, should we try to fetch some Invalidation
     * Descriptors if there are any when Queued Invalidation is enabled?
     */
}

static void vtd_handle_fectl_write(IntelIOMMUState *s)
{
    uint32_t fectl_reg;
    /* FIXME: when software clears the IM field, check the IP field. But do we
     * need to compare the old value and the new value to conclude that
     * software clears the IM field? Or just check if the IM field is zero?
     */
    fectl_reg = vtd_get_long_raw(s, DMAR_FECTL_REG);
    if ((fectl_reg & VTD_FECTL_IP) && !(fectl_reg & VTD_FECTL_IM)) {
        vtd_generate_interrupt(s, DMAR_FEADDR_REG, DMAR_FEDATA_REG);
        vtd_set_clear_mask_long(s, DMAR_FECTL_REG, VTD_FECTL_IP, 0);
        VTD_DPRINTF(FLOG, "IM field is cleared, generate "
                    "fault event interrupt");
    }
}

static void vtd_handle_ics_write(IntelIOMMUState *s)
{
    uint32_t ics_reg = vtd_get_long_raw(s, DMAR_ICS_REG);
    uint32_t iectl_reg = vtd_get_long_raw(s, DMAR_IECTL_REG);

    if ((iectl_reg & VTD_IECTL_IP) && !(ics_reg & VTD_ICS_IWC)) {
        vtd_set_clear_mask_long(s, DMAR_IECTL_REG, VTD_IECTL_IP, 0);
        VTD_DPRINTF(INV, "pending completion interrupt condition serviced, "
                    "clear IP field of IECTL_REG");
    }
}

static void vtd_handle_iectl_write(IntelIOMMUState *s)
{
    uint32_t iectl_reg;
    /* FIXME: when software clears the IM field, check the IP field. But do we
     * need to compare the old value and the new value to conclude that
     * software clears the IM field? Or just check if the IM field is zero?
     */
    iectl_reg = vtd_get_long_raw(s, DMAR_IECTL_REG);
    if ((iectl_reg & VTD_IECTL_IP) && !(iectl_reg & VTD_IECTL_IM)) {
        vtd_generate_interrupt(s, DMAR_IEADDR_REG, DMAR_IEDATA_REG);
        vtd_set_clear_mask_long(s, DMAR_IECTL_REG, VTD_IECTL_IP, 0);
        VTD_DPRINTF(INV, "IM field is cleared, generate "
                    "invalidation event interrupt");
    }
}

static uint64_t vtd_mem_read(void *opaque, hwaddr addr, unsigned size)
{
    IntelIOMMUState *s = opaque;
    uint64_t val;

    if (addr + size > DMAR_REG_SIZE) {
        VTD_DPRINTF(GENERAL, "error: addr outside region: max 0x%"PRIx64
                    ", got 0x%"PRIx64 " %d",
                    (uint64_t)DMAR_REG_SIZE, addr, size);
        return (uint64_t)-1;
    }

    switch (addr) {
    /* Root Table Address Register, 64-bit */
    case DMAR_RTADDR_REG:
        if (size == 4) {
            val = s->root & ((1ULL << 32) - 1);
        } else {
            val = s->root;
        }
        break;

    case DMAR_RTADDR_REG_HI:
        assert(size == 4);
        val = s->root >> 32;
        break;

    /* Invalidation Queue Address Register, 64-bit */
    case DMAR_IQA_REG:
        val = s->iq | (vtd_get_quad(s, DMAR_IQA_REG) & VTD_IQA_QS);
        if (size == 4) {
            val = val & ((1ULL << 32) - 1);
        }
        break;

    case DMAR_IQA_REG_HI:
        assert(size == 4);
        val = s->iq >> 32;
        break;

    default:
        if (size == 4) {
            val = vtd_get_long(s, addr);
        } else {
            val = vtd_get_quad(s, addr);
        }
    }
    VTD_DPRINTF(CSR, "addr 0x%"PRIx64 " size %d val 0x%"PRIx64,
                addr, size, val);
    return val;
}

static void vtd_mem_write(void *opaque, hwaddr addr,
                          uint64_t val, unsigned size)
{
    IntelIOMMUState *s = opaque;

    if (addr + size > DMAR_REG_SIZE) {
        VTD_DPRINTF(GENERAL, "error: addr outside region: max 0x%"PRIx64
                    ", got 0x%"PRIx64 " %d",
                    (uint64_t)DMAR_REG_SIZE, addr, size);
        return;
    }

    switch (addr) {
    /* Global Command Register, 32-bit */
    case DMAR_GCMD_REG:
        VTD_DPRINTF(CSR, "DMAR_GCMD_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        vtd_set_long(s, addr, val);
        vtd_handle_gcmd_write(s);
        break;

    /* Context Command Register, 64-bit */
    case DMAR_CCMD_REG:
        VTD_DPRINTF(CSR, "DMAR_CCMD_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            vtd_set_long(s, addr, val);
        } else {
            vtd_set_quad(s, addr, val);
            vtd_handle_ccmd_write(s);
        }
        break;

    case DMAR_CCMD_REG_HI:
        VTD_DPRINTF(CSR, "DMAR_CCMD_REG_HI write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        vtd_handle_ccmd_write(s);
        break;

    /* IOTLB Invalidation Register, 64-bit */
    case DMAR_IOTLB_REG:
        VTD_DPRINTF(INV, "DMAR_IOTLB_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            vtd_set_long(s, addr, val);
        } else {
            vtd_set_quad(s, addr, val);
            vtd_handle_iotlb_write(s);
        }
        break;

    case DMAR_IOTLB_REG_HI:
        VTD_DPRINTF(INV, "DMAR_IOTLB_REG_HI write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        vtd_handle_iotlb_write(s);
        break;

    /* Invalidate Address Register, 64-bit */
    case DMAR_IVA_REG:
        VTD_DPRINTF(INV, "DMAR_IVA_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            vtd_set_long(s, addr, val);
        } else {
            vtd_set_quad(s, addr, val);
        }
        break;

    case DMAR_IVA_REG_HI:
        VTD_DPRINTF(INV, "DMAR_IVA_REG_HI write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        break;

    /* Fault Status Register, 32-bit */
    case DMAR_FSTS_REG:
        VTD_DPRINTF(FLOG, "DMAR_FSTS_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        vtd_handle_fsts_write(s);
        break;

    /* Fault Event Control Register, 32-bit */
    case DMAR_FECTL_REG:
        VTD_DPRINTF(FLOG, "DMAR_FECTL_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        vtd_handle_fectl_write(s);
        break;

    /* Fault Event Data Register, 32-bit */
    case DMAR_FEDATA_REG:
        VTD_DPRINTF(FLOG, "DMAR_FEDATA_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        break;

    /* Fault Event Address Register, 32-bit */
    case DMAR_FEADDR_REG:
        VTD_DPRINTF(FLOG, "DMAR_FEADDR_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        break;

    /* Fault Event Upper Address Register, 32-bit */
    case DMAR_FEUADDR_REG:
        VTD_DPRINTF(FLOG, "DMAR_FEUADDR_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        break;

    /* Protected Memory Enable Register, 32-bit */
    case DMAR_PMEN_REG:
        VTD_DPRINTF(CSR, "DMAR_PMEN_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        break;

    /* Root Table Address Register, 64-bit */
    case DMAR_RTADDR_REG:
        VTD_DPRINTF(CSR, "DMAR_RTADDR_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            vtd_set_long(s, addr, val);
        } else {
            vtd_set_quad(s, addr, val);
        }
        break;

    case DMAR_RTADDR_REG_HI:
        VTD_DPRINTF(CSR, "DMAR_RTADDR_REG_HI write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        break;

    /* Invalidation Queue Tail Register, 64-bit */
    case DMAR_IQT_REG:
        VTD_DPRINTF(INV, "DMAR_IQT_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            vtd_set_long(s, addr, val);
        } else {
            vtd_set_quad(s, addr, val);
        }
        vtd_handle_iqt_write(s);
        break;

    case DMAR_IQT_REG_HI:
        VTD_DPRINTF(INV, "DMAR_IQT_REG_HI write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        /* 19:63 of IQT_REG is RsvdZ, do nothing here */
        break;

    /* Invalidation Queue Address Register, 64-bit */
    case DMAR_IQA_REG:
        VTD_DPRINTF(INV, "DMAR_IQA_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            vtd_set_long(s, addr, val);
        } else {
            vtd_set_quad(s, addr, val);
        }
        break;

    case DMAR_IQA_REG_HI:
        VTD_DPRINTF(INV, "DMAR_IQA_REG_HI write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        break;

    /* Invalidation Completion Status Register, 32-bit */
    case DMAR_ICS_REG:
        VTD_DPRINTF(INV, "DMAR_ICS_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        vtd_handle_ics_write(s);
        break;

    /* Invalidation Event Control Register, 32-bit */
    case DMAR_IECTL_REG:
        VTD_DPRINTF(INV, "DMAR_IECTL_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        vtd_handle_iectl_write(s);
        break;

    /* Invalidation Event Data Register, 32-bit */
    case DMAR_IEDATA_REG:
        VTD_DPRINTF(INV, "DMAR_IEDATA_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        break;

    /* Invalidation Event Address Register, 32-bit */
    case DMAR_IEADDR_REG:
        VTD_DPRINTF(INV, "DMAR_IEADDR_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        break;

    /* Invalidation Event Upper Address Register, 32-bit */
    case DMAR_IEUADDR_REG:
        VTD_DPRINTF(INV, "DMAR_IEUADDR_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        break;

    /* Fault Recording Registers, 128-bit */
    case DMAR_FRCD_REG_0_0:
        VTD_DPRINTF(FLOG, "DMAR_FRCD_REG_0_0 write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            vtd_set_long(s, addr, val);
        } else {
            vtd_set_quad(s, addr, val);
        }
        break;

    case DMAR_FRCD_REG_0_1:
        VTD_DPRINTF(FLOG, "DMAR_FRCD_REG_0_1 write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        break;

    case DMAR_FRCD_REG_0_2:
        VTD_DPRINTF(FLOG, "DMAR_FRCD_REG_0_2 write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            vtd_set_long(s, addr, val);
        } else {
            vtd_set_quad(s, addr, val);
            /* May clear bit 127 (Fault), update PPF */
            vtd_update_fsts_ppf(s);
        }
        break;

    case DMAR_FRCD_REG_0_3:
        VTD_DPRINTF(FLOG, "DMAR_FRCD_REG_0_3 write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        vtd_set_long(s, addr, val);
        /* May clear bit 127 (Fault), update PPF */
        vtd_update_fsts_ppf(s);
        break;

    default:
        VTD_DPRINTF(GENERAL, "error: unhandled reg write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            vtd_set_long(s, addr, val);
        } else {
            vtd_set_quad(s, addr, val);
        }
    }
}

static IOMMUTLBEntry vtd_iommu_translate(MemoryRegion *iommu, hwaddr addr,
                                         bool is_write)
{
    VTDAddressSpace *vtd_as = container_of(iommu, VTDAddressSpace, iommu);
    IntelIOMMUState *s = vtd_as->iommu_state;
    IOMMUTLBEntry ret = {
        .target_as = &address_space_memory,
        .iova = addr,
        .translated_addr = 0,
        .addr_mask = ~(hwaddr)0,
        .perm = IOMMU_NONE,
    };

    if (!s->dmar_enabled) {
        /* DMAR disabled, passthrough, use 4k-page*/
        ret.iova = addr & VTD_PAGE_MASK_4K;
        ret.translated_addr = addr & VTD_PAGE_MASK_4K;
        ret.addr_mask = ~VTD_PAGE_MASK_4K;
        ret.perm = IOMMU_RW;
        return ret;
    }

    vtd_do_iommu_translate(vtd_as, vtd_as->bus_num, vtd_as->devfn, addr,
                           is_write, &ret);
    VTD_DPRINTF(MMU,
                "bus %"PRIu8 " slot %"PRIu8 " func %"PRIu8 " devfn %"PRIu8
                " gpa 0x%"PRIx64 " hpa 0x%"PRIx64, vtd_as->bus_num,
                VTD_PCI_SLOT(vtd_as->devfn), VTD_PCI_FUNC(vtd_as->devfn),
                vtd_as->devfn, addr, ret.translated_addr);
    return ret;
}

static const VMStateDescription vtd_vmstate = {
    .name = "iommu-intel",
    .unmigratable = 1,
};

static const MemoryRegionOps vtd_mem_ops = {
    .read = vtd_mem_read,
    .write = vtd_mem_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
};

static Property vtd_properties[] = {
    DEFINE_PROP_UINT32("version", IntelIOMMUState, version, 0),
    DEFINE_PROP_END_OF_LIST(),
};

/* Do the initialization. It will also be called when reset, so pay
 * attention when adding new initialization stuff.
 */
static void vtd_init(IntelIOMMUState *s)
{
    memset(s->csr, 0, DMAR_REG_SIZE);
    memset(s->wmask, 0, DMAR_REG_SIZE);
    memset(s->w1cmask, 0, DMAR_REG_SIZE);
    memset(s->womask, 0, DMAR_REG_SIZE);

    s->iommu_ops.translate = vtd_iommu_translate;
    s->root = 0;
    s->root_extended = false;
    s->dmar_enabled = false;
    s->iq_head = 0;
    s->iq_tail = 0;
    s->iq = 0;
    s->iq_size = 0;
    s->qi_enabled = false;
    s->iq_last_desc_type = VTD_INV_DESC_NONE;
    s->next_frcd_reg = 0;
    s->cap = VTD_CAP_FRO | VTD_CAP_NFR | VTD_CAP_ND | VTD_CAP_MGAW |
             VTD_CAP_SAGAW | VTD_CAP_MAMV | VTD_CAP_PSI;
    s->ecap = VTD_ECAP_QI | VTD_ECAP_IRO;

    vtd_reset_context_cache(s);
    vtd_reset_iotlb(s);

    /* Define registers with default values and bit semantics */
    vtd_define_long(s, DMAR_VER_REG, 0x10UL, 0, 0);
    vtd_define_quad(s, DMAR_CAP_REG, s->cap, 0, 0);
    vtd_define_quad(s, DMAR_ECAP_REG, s->ecap, 0, 0);
    vtd_define_long(s, DMAR_GCMD_REG, 0, 0xff800000UL, 0);
    vtd_define_long_wo(s, DMAR_GCMD_REG, 0xff800000UL);
    vtd_define_long(s, DMAR_GSTS_REG, 0, 0, 0);
    vtd_define_quad(s, DMAR_RTADDR_REG, 0, 0xfffffffffffff000ULL, 0);
    vtd_define_quad(s, DMAR_CCMD_REG, 0, 0xe0000003ffffffffULL, 0);
    vtd_define_quad_wo(s, DMAR_CCMD_REG, 0x3ffff0000ULL);

    /* Advanced Fault Logging not supported */
    vtd_define_long(s, DMAR_FSTS_REG, 0, 0, 0x11UL);
    vtd_define_long(s, DMAR_FECTL_REG, 0x80000000UL, 0x80000000UL, 0);
    vtd_define_long(s, DMAR_FEDATA_REG, 0, 0x0000ffffUL, 0);
    vtd_define_long(s, DMAR_FEADDR_REG, 0, 0xfffffffcUL, 0);

    /* Treated as RsvdZ when EIM in ECAP_REG is not supported
     * vtd_define_long(s, DMAR_FEUADDR_REG, 0, 0xffffffffUL, 0);
     */
    vtd_define_long(s, DMAR_FEUADDR_REG, 0, 0, 0);

    /* Treated as RO for implementations that PLMR and PHMR fields reported
     * as Clear in the CAP_REG.
     * vtd_define_long(s, DMAR_PMEN_REG, 0, 0x80000000UL, 0);
     */
    vtd_define_long(s, DMAR_PMEN_REG, 0, 0, 0);

    vtd_define_quad(s, DMAR_IQH_REG, 0, 0, 0);
    vtd_define_quad(s, DMAR_IQT_REG, 0, 0x7fff0ULL, 0);
    vtd_define_quad(s, DMAR_IQA_REG, 0, 0xfffffffffffff007ULL, 0);
    vtd_define_long(s, DMAR_ICS_REG, 0, 0, 0x1UL);
    vtd_define_long(s, DMAR_IECTL_REG, 0x80000000UL, 0x80000000UL, 0);
    vtd_define_long(s, DMAR_IEDATA_REG, 0, 0xffffffffUL, 0);
    vtd_define_long(s, DMAR_IEADDR_REG, 0, 0xfffffffcUL, 0);
    /* Treadted as RsvdZ when EIM in ECAP_REG is not supported */
    vtd_define_long(s, DMAR_IEUADDR_REG, 0, 0, 0);

    /* IOTLB registers */
    vtd_define_quad(s, DMAR_IOTLB_REG, 0, 0Xb003ffff00000000ULL, 0);
    vtd_define_quad(s, DMAR_IVA_REG, 0, 0xfffffffffffff07fULL, 0);
    vtd_define_quad_wo(s, DMAR_IVA_REG, 0xfffffffffffff07fULL);

    /* Fault Recording Registers, 128-bit */
    vtd_define_quad(s, DMAR_FRCD_REG_0_0, 0, 0, 0);
    vtd_define_quad(s, DMAR_FRCD_REG_0_2, 0, 0, 0x8000000000000000ULL);
}

/* Should not reset address_spaces when reset because devices will still use
 * the address space they got at first (won't ask the bus again).
 */
static void vtd_reset(DeviceState *dev)
{
    IntelIOMMUState *s = INTEL_IOMMU_DEVICE(dev);

    VTD_DPRINTF(GENERAL, "");
    vtd_init(s);
}

static void vtd_realize(DeviceState *dev, Error **errp)
{
    IntelIOMMUState *s = INTEL_IOMMU_DEVICE(dev);

    VTD_DPRINTF(GENERAL, "");
    memset(s->address_spaces, 0, sizeof(s->address_spaces));
    memory_region_init_io(&s->csrmem, OBJECT(s), &vtd_mem_ops, s,
                          "intel_iommu", DMAR_REG_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->csrmem);
    /* No corresponding destroy */
    s->iotlb = g_hash_table_new_full(vtd_uint64_hash, vtd_uint64_equal,
                                     g_free, g_free);
    vtd_init(s);
}

static void vtd_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->reset = vtd_reset;
    dc->realize = vtd_realize;
    dc->vmsd = &vtd_vmstate;
    dc->props = vtd_properties;
}

static const TypeInfo vtd_info = {
    .name          = TYPE_INTEL_IOMMU_DEVICE,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(IntelIOMMUState),
    .class_init    = vtd_class_init,
};

static void vtd_register_types(void)
{
    VTD_DPRINTF(GENERAL, "");
    type_register_static(&vtd_info);
}

type_init(vtd_register_types)
