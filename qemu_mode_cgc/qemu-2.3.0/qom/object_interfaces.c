#include "qom/object_interfaces.h"
#include "qemu/module.h"

void user_creatable_complete(Object *obj, Error **errp)
{

    UserCreatableClass *ucc;
    UserCreatable *uc =
        (UserCreatable *)object_dynamic_cast(obj, TYPE_USER_CREATABLE);

    if (!uc) {
        return;
    }

    ucc = USER_CREATABLE_GET_CLASS(uc);
    if (ucc->complete) {
        ucc->complete(uc, errp);
    }
}

bool user_creatable_can_be_deleted(UserCreatable *uc, Error **errp)
{

    UserCreatableClass *ucc = USER_CREATABLE_GET_CLASS(uc);

    if (ucc->can_be_deleted) {
        return ucc->can_be_deleted(uc, errp);
    } else {
        return true;
    }
}

static void register_types(void)
{
    static const TypeInfo uc_interface_info = {
        .name          = TYPE_USER_CREATABLE,
        .parent        = TYPE_INTERFACE,
        .class_size = sizeof(UserCreatableClass),
    };

    type_register_static(&uc_interface_info);
}

type_init(register_types)
