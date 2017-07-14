#ifndef TEST_UTILS_AUTH_H
#define TEST_UTILS_AUTH_H

#include <dbus/dbus.h>
#include "test-utils.h"
#include <dbus/dbus-transport.h>
#include <glib.h>

DBusSocket
test_connect_to_bus_simple (TestMainContext *ctx,
                            const gchar     *address);

#endif