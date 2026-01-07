#include <config.h>

#include <dbus/dbus.h>

#include <stdlib.h>
#include <winsock2.h>

#include "test-utils-glib.h"
#include "test-utils-auth.h"

typedef struct {
    gboolean skip;
    DBusError e;
    TestMainContext *ctx;

    GPid daemon_pid;
    DBusServer *server;

    gchar *address;

    DBusSocket sock;

    size_t message_limit;
    CredHandle credentials;
    DBusString plaintext;
    CtxtHandle context;
    int free_context;

    /* The moment when we start to screw with the data being sent.
     * phase 0 - don't do anything, just a successful auth
     * phase 1 - corrupt the initial client->server AUTH message
     * phase 2 - corrupt the first server->client DATA message
     * phase 3 - corrupt the first client->server DATA message
     * There's no phase 4 (server responds with OK, but SSPI is not playing any part in that)
     */
    int phase;
    /* offset of the byte to corrupt. Increases by 1 with each iteration.
     * Once it goes past the end of the data, advance to the next phase.
     */
    unsigned int corrupt_offset;

    DBusString      outgoing;
    int             free_outgoing;
    DBusString      incoming;
    int             free_incoming;
    DBusString      decoded;
    int             free_decoded;
} Fixture;

typedef struct {
    const char *bug_ref;
    guint min_messages;
    const char *config_file;
    enum { SPECIFY_ADDRESS = 0, RELY_ON_DEFAULT } connect_mode;
} Config;

static void
setup (Fixture       *f,
       gconstpointer  context)
{
  const Config    *config = context;
  SECURITY_STATUS  ss;
  PSecPkgInfoW     sec_package_info;
  TimeStamp        lifetime;
  wchar_t          ntlm_ssp_name[] = L"NTLM";

  ss = QuerySecurityPackageInfoW (ntlm_ssp_name, &sec_package_info);
  g_assert (ss == SEC_E_OK);
  f->message_limit = sec_package_info->cbMaxToken;
  ss = FreeContextBuffer (sec_package_info);
  g_assert (ss == SEC_E_OK);
  ss = AcquireCredentialsHandleW (NULL, ntlm_ssp_name, SECPKG_CRED_OUTBOUND, 0, 0, 0, 0,
                                  &f->credentials, &lifetime);
  g_assert (ss == SEC_E_OK);
  g_assert (_dbus_string_init (&f->plaintext));
  _dbus_string_set_length (&f->plaintext, f->message_limit);

  f->ctx = test_main_context_get ();
  dbus_error_init (&f->e);

  f->address = test_get_dbus_daemon (config ? config->config_file : NULL,
                                     TEST_USER_ME, NULL,
                                     &f->daemon_pid);

  if (f->address == NULL)
    {
      f->skip = TRUE;
      return;
    }

  f->sock.sock = INVALID_SOCKET;

  f->phase = 0;
  f->corrupt_offset = 0;

  f->free_context = 0;
  f->free_outgoing = 0;
  f->free_incoming = 0;
  f->free_decoded = 0;
}

/* Returns TRUE to mean "keep calling me, i still have other ways
 * to corrupt the data".
 * Returns FALSE to mean "i'm done, don't call me again".
 */
static dbus_bool_t
do_corrupt_sspi_auth (Fixture       *f,
                      gconstpointer  context)
{
  SECURITY_STATUS ss;
  TimeStamp       lifetime;
  SecBuffer       output_sec_buffer = { 0, SECBUFFER_TOKEN, NULL};
  SecBufferDesc   output_sec_buffers_descriptor = { SECBUFFER_VERSION, 1, &output_sec_buffer };
  ULONG           attributes;
  volatile int    bytes_written;
  volatile int    bytes_read;
  char           *buffer;
  SecBuffer       input_sec_buffer = { 0, SECBUFFER_TOKEN, NULL};
  SecBufferDesc   input_sec_buffers_descriptor = { SECBUFFER_VERSION, 1, &input_sec_buffer };
  int             end;
  int             to_read, total_read;
#define PHASES 4
  char            expect_error_in_phase[PHASES];
  unsigned long   bytes_available;
  char            zero;
  int             old_offset, old_phase;

  old_offset = f->corrupt_offset;
  old_phase = f->phase;

  if (_dbus_socket_is_valid (f->sock))
    {
      /* Ensure that there's no leftover incoming data in the socket */
      do
      {
#define HUNDRED 100
        char buf[HUNDRED];
        bytes_available = 0;
        ioctlsocket (f->sock.sock, FIONREAD, &bytes_available);
        bytes_read = 0;
        if (bytes_available > 0)
          bytes_read = recv (f->sock.sock, buf, bytes_available > HUNDRED ? HUNDRED : bytes_available, 0);
#undef HUNDRED
      } while (bytes_read > 0);
    }

  if (!_dbus_socket_is_valid (f->sock))
    {
      f->sock = test_connect_to_bus_simple (f->ctx, f->address);
      g_assert (_dbus_socket_is_valid (f->sock));
      zero = 0;
      g_assert (send (f->sock.sock, &zero, 1, 0) == 1);
    }

#define HANDLE_BAD_RECV \
  if (bytes_read < 0) \
    { \
      g_print ("disconnected unexpectedly\n"); \
      f->corrupt_offset = old_offset; \
      f->phase = old_phase; \
      _dbus_close_socket (&f->sock, NULL); \
      _dbus_socket_invalidate (&f->sock); \
 \
      return TRUE; \
    }

#define HANDLE_BAD_SEND \
  if (bytes_written < 0) \
    { \
      g_print ("disconnected unexpectedly\n"); \
      f->corrupt_offset = old_offset; \
      f->phase = old_phase; \
      _dbus_close_socket (&f->sock, NULL); \
      _dbus_socket_invalidate (&f->sock); \
 \
      return TRUE; \
    }

  g_assert (_dbus_string_init (&f->outgoing));
  f->free_outgoing = 1;
  g_assert (_dbus_string_append (&f->outgoing, "AUTH DBUS_WINDOWS_SSPI_NTLM "));

  output_sec_buffer.cbBuffer = _dbus_string_get_length (&f->plaintext);
  output_sec_buffer.pvBuffer = _dbus_string_get_data (&f->plaintext);

  g_print ("\nInit security context\n");
  ss = InitializeSecurityContextW (&f->credentials,
                                   NULL,
                                   NULL,
                                   ISC_REQ_IDENTIFY,
                                   0,
                                   SECURITY_NATIVE_DREP,
                                   NULL,
                                   0,
                                   &f->context,
                                   &output_sec_buffers_descriptor,
                                   &attributes,
                                   &lifetime);

  f->free_context = 1;

  g_assert (ss == SEC_E_OK ||
            ss == SEC_I_COMPLETE_AND_CONTINUE ||
            ss == SEC_I_COMPLETE_NEEDED ||
            ss == SEC_I_CONTINUE_NEEDED);

  if ((SEC_I_COMPLETE_NEEDED == ss) || (SEC_I_COMPLETE_AND_CONTINUE == ss))
    {
      ss = CompleteAuthToken (&f->context,
                              &output_sec_buffers_descriptor);
      g_assert (ss == SEC_E_OK);
    }

  _dbus_string_set_length (&f->plaintext, output_sec_buffer.cbBuffer);

  memset (expect_error_in_phase, 0, PHASES);

  g_print ("phase 1\n");
  if (f->phase == 1)
    {
      if (f->corrupt_offset < output_sec_buffer.cbBuffer && f->corrupt_offset < 32)
        {
          BYTE x = ((BYTE *) output_sec_buffer.pvBuffer)[f->corrupt_offset];
          x = (x == 255 ? 0 : x + 1);
          ((BYTE *) output_sec_buffer.pvBuffer)[f->corrupt_offset] = x;

          switch (f->corrupt_offset)
            {
            /* 4 bytes (12, 13, 14, 15) are flags, changing some of them makes no difference */
            case 13:
            case 14:
            case 15:
            /* 2 bytes (16, 17) is domain SB lengh */
            /* 2 bytes (18, 19) is domain SB allocated space, changing it makes no difference */
            case 18:
            case 19:
              g_print ("corrupted byte %d in phase %d, auth will succeed anyway\n", f->corrupt_offset, f->phase);
              break;
            /* 2 bytes (24, 25) is workstation SB length, changing it causes an error later on */
            case 24:
              g_print ("corrupted byte %d in phase %d, auth will fail in phase 3\n", f->corrupt_offset, f->phase);
              expect_error_in_phase[3] = TRUE;
              break;
            /* 2 bytes (26, 27) is workstation SB allocated space, changing it makes no difference */
            case 26:
            case 27:
              g_print ("corrupted byte %d in phase %d, auth will succeed anyway\n", f->corrupt_offset, f->phase);
              break;
            /* 4 bytes (28, 29, 30, 31) is workstation SB offset, changing it causes an error later on */
            case 28:
              g_print ("corrupted byte %d in phase %d, auth will fail in phase 3\n", f->corrupt_offset, f->phase);
              expect_error_in_phase[3] = TRUE;
              break;
            /* 1 byte (32) is OS major version, changing it makes no difference */
            case 32:
            /* 1 byte (33) is OS minor version, changing it makes no difference */
            case 33:
            /* 2 byte (34, 35) is OS build number, changing it makes no difference */
            case 34:
            case 35:
            /* 4 bytes (36, 37, 38, 39) are unknown/reserved, changing them makes no difference */
            case 36:
            case 37:
            case 38:
            case 39:
              g_print ("corrupted byte %d in phase %d, auth will succeed anyway\n", f->corrupt_offset, f->phase);
              break;
            default:
              if (f->corrupt_offset >= 40)
                {
                  /* Data section starts at byte 40, its length depends on the argument we used, and changing it causes an error later on */
                  g_print ("corrupted byte %d in phase %d, auth will fail in phase 3\n", f->corrupt_offset, f->phase);
                  expect_error_in_phase[3] = TRUE;
                }
              else
                {
                  g_print ("corrupted byte %d in phase %d, auth will fail in phase 1\n", f->corrupt_offset, f->phase);
                  expect_error_in_phase[1] = TRUE;
                }
            }

          f->corrupt_offset += 1;
        }
      else
        {
          f->phase += 1;
          f->corrupt_offset = 0;
          g_print ("will begin corrupting phase %d\n", f->phase);
        }
    }

  g_assert (_dbus_string_hex_encode (&f->plaintext, 0, &f->outgoing, _dbus_string_get_length (&f->outgoing)));
  g_assert (_dbus_string_append (&f->outgoing, "\r\n"));

  _dbus_verbose ("sending `%.*s`\n", _dbus_string_get_length (&f->outgoing), _dbus_string_get_data (&f->outgoing));
  bytes_written = send (f->sock.sock,
                        _dbus_string_get_data (&f->outgoing), _dbus_string_get_length (&f->outgoing),
                        0);
  HANDLE_BAD_SEND
  g_assert (bytes_written == _dbus_string_get_length (&f->outgoing));

#define DATASTR "DATA "
#define DATASTRLEN strlen (DATASTR)
#define REJSTR "REJECTED"
#define REJSTRLEN strlen (REJSTR)
  g_assert (_dbus_string_init (&f->incoming));
  f->free_incoming = 1;

  g_print ("receiving in phase 1\n");
  g_assert (_dbus_string_set_length (&f->incoming, 100));
  buffer = _dbus_string_get_data (&f->incoming);
  bytes_read = recv (f->sock.sock, buffer, 100, MSG_PEEK);
  HANDLE_BAD_RECV

  g_print ("received %.*s\n", bytes_read, buffer);

  if (f->phase <= 1 && (expect_error_in_phase[1] != FALSE))
    {
      g_assert (bytes_read >= (int) REJSTRLEN);
      g_assert (strncmp (buffer, REJSTR, REJSTRLEN) == 0);

      g_print ("auth failed in phase 1\n");
      return TRUE;
    }

  g_assert (bytes_read >= (int) DATASTRLEN);
  g_assert (strncmp (buffer, DATASTR, DATASTRLEN) == 0);

  _dbus_string_free (&f->outgoing);
  f->free_outgoing = 0;

  to_read = 0;
  total_read = 0;
  do
  {
    int i, should_break;
    for (i = 0, should_break = FALSE; i < total_read - 1; i++)
      {
        if (buffer[i] == '\r' && buffer[i + 1] == '\n')
          {
            should_break = TRUE;
            total_read = i + 2;
          }
      }
    if (should_break)
      break;
    to_read += 100;
    g_assert (_dbus_string_set_length (&f->incoming, to_read));
    buffer = _dbus_string_get_data (&f->incoming);
    bytes_read = recv (f->sock.sock, &buffer[total_read], 100, 0);
    HANDLE_BAD_RECV
    g_assert (bytes_read > 0);
    total_read += bytes_read;
  } while (TRUE);
  g_assert (buffer[total_read - 2] == '\r' &&
            buffer[total_read - 1] == '\n');
  buffer[total_read - 1] = buffer[total_read - 2] = '\0';

  g_assert (_dbus_string_init (&f->decoded));
  f->free_decoded = 1;
  g_assert (_dbus_string_hex_decode (&f->incoming, DATASTRLEN, &end, &f->decoded, 0));
  g_assert (end == total_read - 2);
  _dbus_string_free (&f->incoming);
  f->free_incoming = 0;

  input_sec_buffer.cbBuffer = _dbus_string_get_length (&f->decoded);
  input_sec_buffer.pvBuffer = (void *) _dbus_string_get_const_data (&f->decoded);

  g_assert (input_sec_buffer.cbBuffer > 0);

  g_print ("phase 2\n");
  if (f->phase == 2)
    {
      /* 2 bytes (40, 41) is target info SB length, changing it makes no difference */
      /* 2 bytes (42, 43) is target info SB allocated space, changing it makes no difference */
      /* 4 bytes (44, 45, 46, 47) is target info SB offset, changing it makes no difference */
      /* Data section starts at byte 48, its length depends on the argument we used, and changing it makes no difference
       * because of local authentication.
       */
      if (f->corrupt_offset < input_sec_buffer.cbBuffer && f->corrupt_offset < 40)
        {
          BYTE x = ((BYTE *) input_sec_buffer.pvBuffer)[f->corrupt_offset];
          x = (x == 255 ? 0 : x + 1);
          ((BYTE *) input_sec_buffer.pvBuffer)[f->corrupt_offset] = x;

          switch (f->corrupt_offset)
            {
            /* 8 bytes (32, 33, 34, 35, 36, 37, 38, 39) is the context, changing it causes an error later on */
            case 32:
            case 33:
            case 34:
            case 35:
            case 36:
            case 37:
            case 38:
            case 39:
              g_print ("corrupted byte %d in phase %d, auth will fail in phase 3\n", f->corrupt_offset, f->phase);
              expect_error_in_phase[3] = TRUE;
              break;
            default:
              if (f->corrupt_offset >= 12 && f->corrupt_offset < 32)
                {
                  /* 2 bytes (12, 13) is target name SB length, changing it makes no difference */
                  /* 2 bytes (14, 15) is target name SB allocated space, changing it makes no difference */
                  /* 4 bytes (16, 17, 18, 19) is target name SB offset, changing it makes no difference */
                  /* 4 bytes (20, 21, 22, 23) are flags, changing some of them makes no difference */
                  /* 8 bytes (24, 25, 26, 27, 28, 29, 30, 31) is the challenge, changing it makes no difference (yes! Because of local authentication) */
                  g_print ("corrupted byte %d in phase %d, auth will succeed anyway. Skipping to offset 31\n", f->corrupt_offset, f->phase);
                  f->corrupt_offset = 31;
                }
              else
                {
                  g_print ("corrupted byte %d in phase %d, auth will fail in phase 2\n", f->corrupt_offset, f->phase);
                  expect_error_in_phase[2] = TRUE;
                }
            }

          f->corrupt_offset += 1;
        }
      else
        {
          f->phase += 1;
          f->corrupt_offset = 0;
          g_print ("win begin corrupting phase %d", f->phase);
        }
    }

  g_assert (_dbus_string_init (&f->outgoing));
  f->free_outgoing = 1;
  g_assert (_dbus_string_append (&f->outgoing, "DATA "));

  _dbus_string_set_length (&f->plaintext, f->message_limit);
  output_sec_buffer.cbBuffer = _dbus_string_get_length (&f->plaintext);
  output_sec_buffer.pvBuffer = _dbus_string_get_data (&f->plaintext);

  ss = InitializeSecurityContextW (&f->credentials,
                                   &f->context,
                                   NULL,
                                   ISC_REQ_IDENTIFY,
                                   0,
                                   SECURITY_NATIVE_DREP,
                                   &input_sec_buffers_descriptor,
                                   0,
                                   &f->context,
                                   &output_sec_buffers_descriptor,
                                   &attributes,
                                   &lifetime);

  g_print ("getting ISC result\n");
  if (f->phase <= 2 && expect_error_in_phase[2] != FALSE)
    {
      g_assert (ss != SEC_E_OK &&
                ss != SEC_I_COMPLETE_AND_CONTINUE &&
                ss != SEC_I_COMPLETE_NEEDED &&
                ss != SEC_I_CONTINUE_NEEDED);

      g_print ("ISC failed, aborting auth\n");
      /* Server still thinks we're doing AUTH, make sure it fails */
#define FAKEAUTHDATA "DATA baadf00d\r\n"
#define FAKEAUTHDATALEN strlen (FAKEAUTHDATA)
      bytes_written = send (f->sock.sock, FAKEAUTHDATA, FAKEAUTHDATALEN, 0);
      HANDLE_BAD_SEND
      g_assert (bytes_written == FAKEAUTHDATALEN);

      g_assert (_dbus_string_init (&f->incoming));
      f->free_incoming = 1;
      g_assert (_dbus_string_set_length (&f->incoming, 100));
      buffer = _dbus_string_get_data (&f->incoming);
      bytes_read = recv (f->sock.sock, buffer, 100, MSG_PEEK);
      HANDLE_BAD_RECV
      g_print ("received %.*s\n", bytes_read, buffer);
      g_assert (bytes_read >= (int) REJSTRLEN);
      g_assert (strncmp (buffer, REJSTR, REJSTRLEN) == 0);

      g_print ("auth failed in phase 2\n");
      return TRUE;
    }

  g_assert (ss == SEC_E_OK ||
            ss == SEC_I_COMPLETE_AND_CONTINUE ||
            ss == SEC_I_COMPLETE_NEEDED ||
            ss == SEC_I_CONTINUE_NEEDED);

  if ((SEC_I_COMPLETE_NEEDED == ss) || (SEC_I_COMPLETE_AND_CONTINUE == ss))
    {
      ss = CompleteAuthToken (&f->context,
                              &output_sec_buffers_descriptor);
      g_assert (ss == SEC_E_OK);
    }

  _dbus_string_set_length (&f->plaintext, output_sec_buffer.cbBuffer);

  g_print ("phase 3\n");
  if (f->phase == 3)
    {
      /* Session key starts at byte 52, everything from that point is irrelevant */
      if (f->corrupt_offset < output_sec_buffer.cbBuffer && f->corrupt_offset < 52)
        {
          BYTE x = ((BYTE *)output_sec_buffer.pvBuffer)[f->corrupt_offset];
          x = (x == 255 ? 0 : x + 1);
          ((BYTE *)output_sec_buffer.pvBuffer)[f->corrupt_offset] = x;

          switch (f->corrupt_offset)
            {
            /* 2 bytes (12, 13) is LM Response SB length, changing it causes an error */
            case 12:
            case 13:
            /* 2 bytes (20, 21) is NTLM Response SB length, changing it causes an error */
            case 20:
            case 21:
            /* 2 bytes (28, 29) is Target Name SB length, changing it causes an error */
            case 28:
            case 29:
            /* 2 bytes (36, 37) is User Name SB length, changing it causes an error */
            case 36:
            case 37:
            /* 2 bytes (44, 45) is Workstation Name SB length, changing it causes an error */
            case 44:
            case 45:
              g_print ("corrupted byte %d in phase %d, auth will fail in phase 3\n", f->corrupt_offset, f->phase);
              expect_error_in_phase[3] = TRUE;
              break;
            default:
              if ((f->corrupt_offset > 13 && f->corrupt_offset < 20) ||
                  (f->corrupt_offset > 21 && f->corrupt_offset < 28) ||
                  (f->corrupt_offset > 29 && f->corrupt_offset < 36) ||
                  (f->corrupt_offset > 37 && f->corrupt_offset < 44) ||
                  (f->corrupt_offset > 45 && f->corrupt_offset < 52))
                {
                  /* 2 bytes (14, 15) is LM Response SB allocated space, changing it makes no difference */
                  /* 4 bytes (16, 17, 18, 19) is LM Response SB offset, changing it makes no difference */
                  /* 2 bytes (22, 23) is NTLM Response SB allocated space, changing it makes no difference */
                  /* 4 bytes (24, 25, 26, 27) is NTLM Response SB offset, changing it makes no difference */
                  /* and so on for Target Name, User name and Workstation Name */
                  g_print ("corrupted byte %d in phase %d, auth will succeed anyway\n", f->corrupt_offset, f->phase);
                }
              else
                {
                  g_print ("corrupted byte %d in phase %d, auth will fail in phase 3\n", f->corrupt_offset, f->phase);
                  expect_error_in_phase[3] = TRUE;
                }
            }

          f->corrupt_offset += 1;
        }
      else
        {
          f->phase += 1;
          f->corrupt_offset = 0;
          g_print ("stopping corruption\n");
        }
    }

  g_assert (_dbus_string_hex_encode (&f->plaintext, 0, &f->outgoing,
                                     _dbus_string_get_length (&f->outgoing)));

  g_assert (_dbus_string_append (&f->outgoing, "\r\n"));

  bytes_written = send (f->sock.sock,
                        _dbus_string_get_data (&f->outgoing), _dbus_string_get_length (&f->outgoing),
                        0);
  HANDLE_BAD_SEND
  g_assert (bytes_written == _dbus_string_get_length (&f->outgoing));

#undef DATASTR
#undef DATASTRLEN
  g_print ("receiving in phase 3\n");

  g_assert (_dbus_string_init (&f->incoming));
  f->free_incoming = 1;
  g_assert (_dbus_string_set_length (&f->incoming, 100));
  buffer = _dbus_string_get_data (&f->incoming);
  bytes_read = recv (f->sock.sock, buffer, 100, MSG_PEEK);
  HANDLE_BAD_RECV
  g_print ("received %.*s\n", bytes_read, buffer);

  if (f->phase <= 3 && expect_error_in_phase[3] != FALSE)
    {
      g_assert (bytes_read >= (int) REJSTRLEN);
      g_assert (strncmp (buffer, REJSTR, REJSTRLEN) == 0);

      g_print ("auth failed in phase 3\n");

      return TRUE;
    }

#undef REJSTR
#undef REJSTRLEN

#define OKSTR "OK "
#define OKSTRLEN strlen (OKSTR)

  g_assert (bytes_read >= (int) OKSTRLEN);
  g_assert (strncmp (buffer, OKSTR, OKSTRLEN) == 0);

  g_print ("auth succeeded\n");

#undef OKSTR
#undef OKSTRLEN

  /* Can't re-attempt AUTH after OK, must tear the connection down */
  _dbus_close_socket (&f->sock, NULL);
  _dbus_socket_invalidate (&f->sock);

  _dbus_string_free (&f->outgoing);
  f->free_outgoing = 0;

  _dbus_string_free (&f->incoming);
  f->free_incoming = 0;

  DeleteSecurityContext (&f->context);
  f->free_context = 0;

  if (f->phase == 0)
    {
      f->phase += 1;
      g_print ("will begin corrupting phase %d\n", f->phase);
    }
  else if (f->phase >= 4)
    return FALSE;

  return TRUE;
}

static void
test_sspi_corrupt (Fixture       *f,
                   gconstpointer  context)
{
  while (TRUE)
  {
    /* clean up after previous iteration */
    if (f->free_context)
      {
        DeleteSecurityContext (&f->context);
        f->free_context = 0;
      }

    if (f->free_outgoing)
      {
        f->free_outgoing = 0;
        _dbus_string_free (&f->outgoing);
      }
    if (f->free_incoming)
      {
        f->free_incoming = 0;
        _dbus_string_free (&f->incoming);
      }
    if (f->free_decoded)
      {
        f->free_decoded = 0;
        _dbus_string_free (&f->decoded);
      }

    if (!do_corrupt_sspi_auth (f, context))
      break;
  }
}

static void
teardown (Fixture       *f,
          gconstpointer  context G_GNUC_UNUSED)
{
  SECURITY_STATUS ss;

  if (_dbus_socket_is_valid (f->sock))
    {
      _dbus_close_socket (&f->sock, NULL);
      _dbus_socket_invalidate (&f->sock);
    }

  ss = FreeCredentialsHandle (&f->credentials);
  g_assert (ss == SEC_E_OK);
  _dbus_string_free (&f->plaintext);

  dbus_error_free (&f->e);

  if (f->daemon_pid != 0)
    {
      test_kill_pid (f->daemon_pid);
      g_spawn_close_pid (f->daemon_pid);
      f->daemon_pid = 0;
    }

  test_main_context_unref (f->ctx);
  g_free (f->address);
}

static Config sspi_corrupt_config = {
    "96577", 1, "valid-config-files/debug-auth-sspi.conf",
    SPECIFY_ADDRESS
};

int
main (int argc,
    char **argv)
{
  test_init (&argc, &argv);

  g_test_add ("/auth/sspi-corrupt", Fixture, &sspi_corrupt_config, setup, test_sspi_corrupt, teardown);

  return g_test_run ();

  return 0;
}
