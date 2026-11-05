/*
 * SPDX-FileCopyrightText: Ralf Habacker <ralf.habacker@freenet.de>
 * SPDX-License-Identifier: MIT
 */

#include <dbus/dbus.h>

int main(void)
{
    DBusError error;
    dbus_error_init (&error);
    dbus_set_error (&error, "org.example.Error", "message");
    dbus_error_free (&error);
    return 0;
}
