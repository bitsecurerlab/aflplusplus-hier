/*
 * vhost-user.h
 *
 * Copyright (c) 2013 Virtual Open Systems Sarl.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef VHOST_USER_H_
#define VHOST_USER_H_

struct vhost_net;
struct vhost_net *vhost_user_get_vhost_net(NetClientState *nc);

#endif /* VHOST_USER_H_ */
