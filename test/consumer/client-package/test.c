/*
 * SPDX-FileCopyrightText: Ralf Habacker <ralf.habacker@freenet.de>
 * SPDX-License-Identifier: MIT
 */

#include <dbus/dbus.h>
#include <stddef.h>

int main(void)
{
    DBusError error;
    dbus_error_init (&error);
    dbus_set_error (&error, "name", "%s %d %zu %lld", "x", 1, (size_t) 1, (long long) 1);
    dbus_set_error (&error, "org.example.Error", "message");
    dbus_error_free (&error);
    return 0;
}
