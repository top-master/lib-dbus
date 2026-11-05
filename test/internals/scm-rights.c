/*
 * Copyright © 2026 Collabora Ltd.
 * SPDX-License-Identifier: MIT
 */

#include <config.h>

#include <sys/socket.h>

#include <glib/gstdio.h>

#include "dbus/dbus-credentials.h"
#include "dbus/dbus-sysdeps.h"
#include "dbus/dbus-sysdeps-unix.h"
#include "test-utils.h"
#include "test-utils-glib.h"

typedef struct
{
  const char *test_name;
  DBusInitialFDs *initial_fds;
  DBusSocket sender;
  DBusSocket recipient;
  unsigned skip : 1;
} Fixture;

static void
free_n_fds (int *fds,
            int n)
{
  int i;

  for (i = 0; i < n; i++)
    {
      GError *local_error = NULL;

      g_close (fds[i], &local_error);
      g_assert_no_error (local_error);
    }

  g_free (fds);
}

static int *
fixture_open_n_fds (Fixture *f,
                    int n)
{
  int *fds;
  int i;

  g_assert_cmpint (n, >, 0);

  fds = g_new0 (int, n + 1);

  for (i = 0; i < n + 1; i++)
    fds[i] = -1;

  for (i = 0; i < n; i += 2)
    {
      if (pipe (&fds[i]) < 0)
        g_error ("pipe: %s", g_strerror (errno));

      g_assert_cmpint (fds[i], >=, 3);
      g_assert_cmpint (fds[i + 1], >=, 3);
    }

  if (n % 2)
    {
      GError *local_error = NULL;

      g_close (fds[n], &local_error);
      g_assert_no_error (local_error);
      fds[n] = -1;
    }

  g_test_message ("fds that will be sent:");

  for (i = 0; i < n; i++)
    {
      g_test_message ("\t[%d] = %d", i, fds[i]);
      g_assert_cmpint (fds[i], >=, 3);
    }

  g_assert_cmpint (fds[n], ==, -1);
  return fds;
}

static void
fixture_send_byte_with_n_fds (Fixture *f,
                              int *fds,
                              int n)
{
  DBusString send_buffer;
  int bytes_sent;

  g_assert_cmpint (n, >=, 0);

  _dbus_string_init_const (&send_buffer, "x");

  g_test_message ("Sending a byte with %d fds", n);

  do
    {
      bytes_sent = _dbus_write_socket_with_unix_fds (f->sender,
                                                     &send_buffer, 0, 1,
                                                     fds,
                                                     n);

      if (bytes_sent < 0)
        {
          int saved_errno = errno;

          if (_dbus_get_is_errno_eagain_or_ewouldblock (saved_errno))
            bytes_sent = 0;
          else
            g_error ("_dbus_write_socket_with_unix_fds: %s",
                     g_strerror (saved_errno));
        }
    } while (bytes_sent == 0);
}

static void
fixture_receive_byte_with_n_fds (Fixture *f,
                                 size_t accept_n,
                                 const int *expect_fds,
                                 size_t expect_n,
                                 int expect_failure)
{
  const int len = 16;   /* arbitrary */
  DBusString receive_buffer = _DBUS_STRING_INIT_INVALID;
  int bytes_received;
  int *receive_fds;
  unsigned int n_fds;

  g_assert_cmpuint (accept_n, <=, INT_MAX);
  g_assert_cmpuint (expect_n, <=, accept_n);

  if (expect_failure != 0)
    {
      g_assert_null (expect_fds);
      g_assert_cmpuint (expect_n, ==, 0);
    }
  else if (expect_n != 0)
    {
      g_assert_nonnull (expect_fds);
    }

  receive_fds = g_new0 (int, accept_n);

  if (!_dbus_string_init_preallocated (&receive_buffer, len))
    g_error ("OOM");

  g_test_message ("Receiving a byte with up to %" G_GSIZE_FORMAT " fds", accept_n);

  do
    {
      n_fds = (unsigned int) accept_n;
      bytes_received = _dbus_read_socket_with_unix_fds (f->recipient,
                                                        &receive_buffer, len,
                                                        receive_fds,
                                                        &n_fds);

      if (bytes_received < 0)
        {
          int saved_errno = errno;

          if (_dbus_get_is_errno_eagain_or_ewouldblock (saved_errno))
            {
              bytes_received = 0;
            }
          else if (expect_failure != 0)
            {
              g_assert_cmpstr (g_strerror (saved_errno), ==,
                               g_strerror (expect_failure));
              g_assert_cmpint (saved_errno, ==, expect_failure);
            }
          else
            {
              g_error ("_dbus_read_socket_with_unix_fds: %s",
                       g_strerror (saved_errno));
            }
        }
    } while (bytes_received == 0);

  if (expect_failure != 0)
    {
      g_test_message ("Expected failure with %s", g_strerror (expect_failure));
      g_assert_cmpint (bytes_received, <, 0);
      g_assert_cmpuint (n_fds, ==, 0);
    }
  else
    {
      size_t i;

      g_assert_cmpuint (bytes_received, ==, 1);
      g_assert_cmpuint (n_fds, ==, expect_n);

      if (n_fds == 0)
        g_test_message ("no fds received");
      else
        g_test_message ("fds that were received:");

      for (i = 0; i < n_fds; i++)
        {
          struct stat received_sb, expected_sb;

          g_test_message ("\t[%" G_GSIZE_FORMAT "] = %d", i, receive_fds[i]);

          g_assert_cmpint (receive_fds[i], !=, expect_fds[i]);
          g_assert_cmpint (fstat (receive_fds[i], &received_sb) ? errno : 0, ==, 0);
          g_assert_cmpint (fstat (expect_fds[i], &expected_sb) ? errno : 0, ==, 0);
          g_assert_cmpint (received_sb.st_dev, ==, expected_sb.st_dev);
          g_assert_cmpint (received_sb.st_ino, ==, expected_sb.st_ino);
        }
    }

  free_n_fds (receive_fds, n_fds);
  _dbus_string_free (&receive_buffer);
}

static void
setup (Fixture *f,
       const void *context G_GNUC_UNUSED)
{
  const char *error_str = NULL;
  int fds[2];

  f->test_name = "a test that didn't set test_name";
  _dbus_socket_invalidate (&f->sender);
  _dbus_socket_invalidate (&f->recipient);

  /* Ensure that none of the fds we work with will be 0, 1 or 2 */
  if (!_dbus_ensure_standard_fds (0, &error_str))
    g_error ("_dbus_ensure_standard_fds: %s (%s)",
             error_str, g_strerror (errno));

  f->initial_fds = _dbus_check_fdleaks_enter ();

  if (socketpair (AF_UNIX, SOCK_STREAM, 0, fds) < 0)
    {
      gchar *message;

      message = g_strdup_printf ("socketpair: %s", g_strerror (errno));
      g_test_skip (message);
      g_free (message);
      f->skip = TRUE;
      return;
    }

  f->sender.fd = fds[0];
  f->recipient.fd = fds[1];
}

static void
test_normal (Fixture *f,
             const void *context G_GNUC_UNUSED)
{
  const int n = 16;
  int *fds_to_send;

  f->test_name = G_STRFUNC;

  if (f->skip)
    return;

  fds_to_send = fixture_open_n_fds (f, n);

  /* Send a number of fds that exactly fits in the space allowed */
  fixture_send_byte_with_n_fds (f, fds_to_send, n);
  fixture_receive_byte_with_n_fds (f, n, fds_to_send, n, 0);

  /* Send a number of fds for which there is slightly more than enough space */
  fixture_send_byte_with_n_fds (f, fds_to_send, n);
  fixture_receive_byte_with_n_fds (f, n + 1, fds_to_send, n, 0);

  /* Send a number of fds for which there is more than enough space */
  fixture_send_byte_with_n_fds (f, fds_to_send, n);
  fixture_receive_byte_with_n_fds (f, n * 2, fds_to_send, n, 0);

  free_n_fds (fds_to_send, n);
}

static void
test_msg_ctrunc (Fixture *f,
                 const void *context G_GNUC_UNUSED)
{
  const int n = 16;
  int *fds_to_send;

  f->test_name = G_STRFUNC;

  if (f->skip)
    return;

  /* If there are more fds pending than we are ready to receive,
   * then we expect the kernel to report MSG_CTRUNC. */
  fds_to_send = fixture_open_n_fds (f, n + 1);
  fixture_send_byte_with_n_fds (f, fds_to_send, n + 1);
  fixture_receive_byte_with_n_fds (f, n, NULL, 0, ENOSPC);
  free_n_fds (fds_to_send, n + 1);
}

static void
test_none_accepted (Fixture *f,
                    const void *context G_GNUC_UNUSED)
{
  const int n = 1;
  int *fds_to_send;

  f->test_name = G_STRFUNC;

  if (f->skip)
    return;

  fixture_send_byte_with_n_fds (f, NULL, 0);
  fixture_receive_byte_with_n_fds (f, 0, NULL, 0, 0);

  /* If there are more fds pending than we are ready to receive,
   * then we expect the kernel to report MSG_CTRUNC.
   * In particular, if we are not actually accepting *any* fds,
   * then we can't expect to get any. */
  fds_to_send = fixture_open_n_fds (f, n);
  fixture_send_byte_with_n_fds (f, fds_to_send, n);
  fixture_receive_byte_with_n_fds (f, 0, NULL, 0, ENOSPC);
  free_n_fds (fds_to_send, n);
}

static void
test_with_credentials_byte (Fixture *f,
                            const void *context G_GNUC_UNUSED)
{
  DBusError d_error = DBUS_ERROR_INIT;
  const int n = 1;
  int *fds_to_send;
  DBusCredentials *creds;

  f->test_name = G_STRFUNC;

  if (f->skip)
    return;

  creds = _dbus_credentials_new ();

  if (creds == NULL)
    g_error ("OOM");

  fds_to_send = fixture_open_n_fds (f, n);
  fixture_send_byte_with_n_fds (f, fds_to_send, n);

  /* We leave it undefined whether having a fd attached to the
   * initial message will result in _dbus_read_credentials_socket()
   * failing or not; but even if it doesn't fail for that reason,
   * it will fail because the initial byte that we sent in
   * fixture_send_byte_with_n_fds() wasn't the '\0' that the D-Bus
   * protocol requires. */
  if (_dbus_read_credentials_socket (f->recipient, creds, &d_error))
    {
      g_error ("Expected _dbus_read_credentials_socket to fail");
    }
  else
    {
      g_test_message ("_dbus_read_credentials_socket: %s: %s",
                      d_error.name, d_error.message);
      dbus_error_free (&d_error);
    }

  free_n_fds (fds_to_send, n);
  _dbus_credentials_unref (creds);
}

static void
teardown (Fixture *f,
          const void *context G_GNUC_UNUSED)
{
  _dbus_close_socket (&f->sender, NULL);
  _dbus_close_socket (&f->recipient, NULL);
  _dbus_check_fdleaks_leave (f->initial_fds, f->test_name);
}

int
main (int argc,
      char **argv)
{
  int ret;

  test_init (&argc, &argv);

  g_test_add ("/scm_rights/msg_ctrunc",
              Fixture, NULL, setup, test_msg_ctrunc, teardown);
  g_test_add ("/scm_rights/none_accepted",
              Fixture, NULL, setup, test_none_accepted, teardown);
  g_test_add ("/scm_rights/normal",
              Fixture, NULL, setup, test_normal, teardown);
  g_test_add ("/scm_rights/with_credentials_byte",
              Fixture, NULL, setup, test_with_credentials_byte, teardown);

  ret = g_test_run ();
  dbus_shutdown ();
  return ret;
}
