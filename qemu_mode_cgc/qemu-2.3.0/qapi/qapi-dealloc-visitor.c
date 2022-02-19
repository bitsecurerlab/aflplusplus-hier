/*
 * Dealloc Visitor
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Michael Roth   <mdroth@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "qapi/dealloc-visitor.h"
#include "qemu/queue.h"
#include "qemu-common.h"
#include "qapi/qmp/types.h"
#include "qapi/visitor-impl.h"

typedef struct StackEntry
{
    void *value;
    bool is_list_head;
    QTAILQ_ENTRY(StackEntry) node;
} StackEntry;

struct QapiDeallocVisitor
{
    Visitor visitor;
    QTAILQ_HEAD(, StackEntry) stack;
    bool is_list_head;
};

static QapiDeallocVisitor *to_qov(Visitor *v)
{
    return container_of(v, QapiDeallocVisitor, visitor);
}

static void qapi_dealloc_push(QapiDeallocVisitor *qov, void *value)
{
    StackEntry *e = g_malloc0(sizeof(*e));

    e->value = value;

    /* see if we're just pushing a list head tracker */
    if (value == NULL) {
        e->is_list_head = true;
    }
    QTAILQ_INSERT_HEAD(&qov->stack, e, node);
}

static void *qapi_dealloc_pop(QapiDeallocVisitor *qov)
{
    StackEntry *e = QTAILQ_FIRST(&qov->stack);
    QObject *value;
    QTAILQ_REMOVE(&qov->stack, e, node);
    value = e->value;
    g_free(e);
    return value;
}

static void qapi_dealloc_start_struct(Visitor *v, void **obj, const char *kind,
                                      const char *name, size_t unused,
                                      Error **errp)
{
    QapiDeallocVisitor *qov = to_qov(v);
    qapi_dealloc_push(qov, obj);
}

static void qapi_dealloc_end_struct(Visitor *v, Error **errp)
{
    QapiDeallocVisitor *qov = to_qov(v);
    void **obj = qapi_dealloc_pop(qov);
    if (obj) {
        g_free(*obj);
    }
}

static void qapi_dealloc_start_implicit_struct(Visitor *v,
                                               void **obj,
                                               size_t size,
                                               Error **errp)
{
    QapiDeallocVisitor *qov = to_qov(v);
    qapi_dealloc_push(qov, obj);
}

static void qapi_dealloc_end_implicit_struct(Visitor *v, Error **errp)
{
    QapiDeallocVisitor *qov = to_qov(v);
    void **obj = qapi_dealloc_pop(qov);
    if (obj) {
        g_free(*obj);
    }
}

static void qapi_dealloc_start_list(Visitor *v, const char *name, Error **errp)
{
    QapiDeallocVisitor *qov = to_qov(v);
    qapi_dealloc_push(qov, NULL);
}

static GenericList *qapi_dealloc_next_list(Visitor *v, GenericList **listp,
                                           Error **errp)
{
    GenericList *list = *listp;
    QapiDeallocVisitor *qov = to_qov(v);
    StackEntry *e = QTAILQ_FIRST(&qov->stack);

    if (e && e->is_list_head) {
        e->is_list_head = false;
        return list;
    }

    if (list) {
        list = list->next;
        g_free(*listp);
        return list;
    }

    return NULL;
}

static void qapi_dealloc_end_list(Visitor *v, Error **errp)
{
    QapiDeallocVisitor *qov = to_qov(v);
    void *obj = qapi_dealloc_pop(qov);
    assert(obj == NULL); /* should've been list head tracker with no payload */
}

static void qapi_dealloc_type_str(Visitor *v, char **obj, const char *name,
                                  Error **errp)
{
    if (obj) {
        g_free(*obj);
    }
}

static void qapi_dealloc_type_int(Visitor *v, int64_t *obj, const char *name,
                                  Error **errp)
{
}

static void qapi_dealloc_type_bool(Visitor *v, bool *obj, const char *name,
                                   Error **errp)
{
}

static void qapi_dealloc_type_number(Visitor *v, double *obj, const char *name,
                                     Error **errp)
{
}

static void qapi_dealloc_type_size(Visitor *v, uint64_t *obj, const char *name,
                                   Error **errp)
{
}

static void qapi_dealloc_type_enum(Visitor *v, int *obj, const char *strings[],
                                   const char *kind, const char *name,
                                   Error **errp)
{
}

/* If there's no data present, the dealloc visitor has nothing to free.
 * Thus, indicate to visitor code that the subsequent union fields can
 * be skipped. This is not an error condition, since the cleanup of the
 * rest of an object can continue unhindered, so leave errp unset in
 * these cases.
 *
 * NOTE: In cases where we're attempting to deallocate an object that
 * may have missing fields, the field indicating the union type may
 * be missing. In such a case, it's possible we don't have enough
 * information to differentiate data_present == false from a case where
 * data *is* present but happens to be a scalar with a value of 0.
 * This is okay, since in the case of the dealloc visitor there's no
 * work that needs to done in either situation.
 *
 * The current inability in QAPI code to more thoroughly verify a union
 * type in such cases will likely need to be addressed if we wish to
 * implement this interface for other types of visitors in the future,
 * however.
 */
static bool qapi_dealloc_start_union(Visitor *v, bool data_present,
                                     Error **errp)
{
    return data_present;
}

Visitor *qapi_dealloc_get_visitor(QapiDeallocVisitor *v)
{
    return &v->visitor;
}

void qapi_dealloc_visitor_cleanup(QapiDeallocVisitor *v)
{
    g_free(v);
}

QapiDeallocVisitor *qapi_dealloc_visitor_new(void)
{
    QapiDeallocVisitor *v;

    v = g_malloc0(sizeof(*v));

    v->visitor.start_struct = qapi_dealloc_start_struct;
    v->visitor.end_struct = qapi_dealloc_end_struct;
    v->visitor.start_implicit_struct = qapi_dealloc_start_implicit_struct;
    v->visitor.end_implicit_struct = qapi_dealloc_end_implicit_struct;
    v->visitor.start_list = qapi_dealloc_start_list;
    v->visitor.next_list = qapi_dealloc_next_list;
    v->visitor.end_list = qapi_dealloc_end_list;
    v->visitor.type_enum = qapi_dealloc_type_enum;
    v->visitor.type_int = qapi_dealloc_type_int;
    v->visitor.type_bool = qapi_dealloc_type_bool;
    v->visitor.type_str = qapi_dealloc_type_str;
    v->visitor.type_number = qapi_dealloc_type_number;
    v->visitor.type_size = qapi_dealloc_type_size;
    v->visitor.start_union = qapi_dealloc_start_union;

    QTAILQ_INIT(&v->stack);

    return v;
}
