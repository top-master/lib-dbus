#include <config.h>
#include "test-utils-auth.h"
#include "test-utils-glib.h"

static dbus_bool_t
_dbus_win_simple_startup_winsock (void)
{
  /* Straight from MSDN, deuglified */

  WORD wVersionRequested;
  WSADATA wsaData;
  int err;

  wVersionRequested = MAKEWORD (2, 0);

  err = WSAStartup (wVersionRequested, &wsaData);
  if (err != 0)
    {
      _dbus_assert_not_reached ("Could not initialize WinSock");
      _dbus_abort ();
    }

  /* Confirm that the WinSock DLL supports 2.0.  Note that if the DLL
   * supports versions greater than 2.0 in addition to 2.0, it will
   * still return 2.0 in wVersion since that is the version we
   * requested.
   */
  if (LOBYTE (wsaData.wVersion) != 2 ||
      HIBYTE (wsaData.wVersion) != 0)
    {
      _dbus_assert_not_reached ("No usable WinSock found");
      _dbus_abort ();
    }

  return TRUE;
}

static DBusSocket
_dbus_connect_simple_tcp_socket (const char     *host,
                                 const char     *port,
                                 const char     *family)
{
  DBusSocket fd = DBUS_SOCKET_INIT;
  int res;
  struct addrinfo hints;
  struct addrinfo *ai, *tmp;

  if (!_dbus_win_simple_startup_winsock ())
    return _dbus_socket_get_invalid ();

  _DBUS_ZERO (hints);

  if (!family)
    hints.ai_family = AF_UNSPEC;
  else if (!strcmp(family, "ipv4"))
    hints.ai_family = AF_INET;
  else if (!strcmp(family, "ipv6"))
    hints.ai_family = AF_INET6;
  else
    return _dbus_socket_get_invalid ();

  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_socktype = SOCK_STREAM;
#ifdef AI_ADDRCONFIG
  hints.ai_flags = AI_ADDRCONFIG;
#else
  hints.ai_flags = 0;
#endif

  if ((res = getaddrinfo (host, port, &hints, &ai)) != 0 || !ai)
    return _dbus_socket_get_invalid ();

  tmp = ai;
  while (tmp)
    {
      if ((fd.sock = socket (tmp->ai_family, SOCK_STREAM, 0)) == INVALID_SOCKET)
        {
          freeaddrinfo(ai);
          return _dbus_socket_get_invalid ();
        }

      if (connect (fd.sock, (struct sockaddr*) tmp->ai_addr, tmp->ai_addrlen) == SOCKET_ERROR)
        {
          closesocket (fd.sock);
          fd.sock = INVALID_SOCKET;
          tmp = tmp->ai_next;
          continue;
        }

      break;
    }
  freeaddrinfo (ai);

  if (!_dbus_socket_is_valid (fd))
    return _dbus_socket_get_invalid ();

  /* Every SOCKET is also a HANDLE. */
  SetHandleInformation((HANDLE) fd.sock,
                       HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE,
                       0 /*disable both flags*/ );

  return fd;
}

static DBusSocket
_dbus_simple_connection_open_internal (const char *address,
                                       DBusError  *error)
{
  DBusSocket s = DBUS_SOCKET_INIT;
  DBusAddressEntry **entries;
  int len, i;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  _dbus_verbose ("opening simple connection to: %s\n", address);

  if (!dbus_parse_address (address, &entries, &len, error))
    return s;

  for (i = 0; i < len; i++)
    {
      const char *host = dbus_address_entry_get_value (entries[i], "host");
      const char *port = dbus_address_entry_get_value (entries[i], "port");
      const char *family = dbus_address_entry_get_value (entries[i], "family");

      if (port == NULL)
        continue;

      if (host == NULL)
        host = "localhost";

      s = _dbus_connect_simple_tcp_socket (host, port, family);
      if (!_dbus_socket_is_valid (s))
        continue;

      _dbus_verbose ("Successfully connected to tcp socket %s:%s\n",
                     host, port);

      break;
    }

  dbus_address_entries_free (entries);

  return s;
}

DBusSocket
test_connect_to_bus_simple (TestMainContext *ctx,
                            const gchar     *address)
{
  DBusSocket sock;
  DBusError error = DBUS_ERROR_INIT;

  sock = _dbus_simple_connection_open_internal (address, &error);
  test_assert_no_error (&error);
  g_assert (_dbus_socket_is_valid (sock));

  return sock;
}
