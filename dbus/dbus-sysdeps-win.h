/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-sysdeps.c Wrappers around system/libc features (internal to D-BUS implementation)
 *
 * Copyright (C) 2002, 2003  Red Hat, Inc.
 * Copyright (C) 2003 CodeFactory AB
 * Copyright (C) 2005 Novell, Inc.
 *
 * SPDX-License-Identifier: AFL-2.1 OR GPL-2.0-or-later
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef DBUS_SYSDEPS_WIN_H
#define DBUS_SYSDEPS_WIN_H

#define SECURITY_WIN32

extern void *_dbus_win_get_dll_hmodule (void);
#define WIN32_LEAN_AND_MEAN

#include "dbus-hash.h"
#include "dbus-string.h"
#include "dbus-threads-internal.h"
#include <ctype.h>
#include <malloc.h>
#include <windows.h>
#undef interface

#ifndef DBUS_WINCE
#include <sspi.h>
#include <sddl.h>
#endif

#define DBUS_CONSOLE_DIR "/var/run/console/"


void _dbus_win_set_errno (int err);
DBUS_PRIVATE_EXPORT
const char* _dbus_win_error_from_last_error (void);

dbus_bool_t _dbus_win_startup_winsock (void);
void _dbus_win_warn_win_error  (const char *message,
                                unsigned long code);
DBUS_PRIVATE_EXPORT
char * _dbus_win_error_string (int error_number);
DBUS_PRIVATE_EXPORT
void _dbus_win_free_error_string (char *string);

extern const char* _dbus_lm_strerror  (int error_number);


dbus_bool_t _dbus_win_account_to_sid (const wchar_t *waccount,
                                      void         **ppsid,
                                      DBusError     *error);

dbus_bool_t
_dbus_win32_sid_to_name_and_domain (dbus_uid_t  uid,
                                    wchar_t   **wname,
                                    wchar_t   **wdomain,
                                    DBusError  *error);


/* Don't define DBUS_CONSOLE_DIR on Win32 */

wchar_t    *_dbus_win_utf8_to_utf16 (const char  *str,
                                     DBusError   *error);
char       *_dbus_win_utf16_to_utf8 (const wchar_t *str,
                                     DBusError *error);

DBUS_PRIVATE_EXPORT
void        _dbus_win_set_error_from_win_error (DBusError *error, int code);

dbus_bool_t
_dbus_win_sid_to_name_and_domain (dbus_uid_t uid,
                                  wchar_t  **wname,
                                  wchar_t  **wdomain,
                                  DBusError *error);

DBUS_PRIVATE_EXPORT
dbus_bool_t _dbus_get_install_root (DBusString *str);

DBUS_PRIVATE_EXPORT
dbus_bool_t _dbus_getsid        (char       **sid,
                                 dbus_pid_t   process_id);

DBUS_PRIVATE_EXPORT
dbus_bool_t _dbus_get_token_sid (char       **sid,
                                 HANDLE       token,
                                 DBusError   *error);

/** Information for SSPI NTLM authentication */
typedef struct DBusSSPINTLMInfo DBusSSPINTLMInfo;

/**
 * Information for SSPI NTLM authentication
 */
struct DBusSSPINTLMInfo
{
#ifndef DBUS_WINCE
  CredHandle    credentials;          /**< SSPI Credentials. */
  CtxtHandle    context;              /**< SSPI Context. */
  size_t        message_limit;        /**< Maximum size of an SSPI NTLM message. */
  char         *output_buffer;        /**< Pre-allocated buffer for an SSPI NTLM message. */
  unsigned int  free_credentials : 1; /**< Must free credentials on shutdown */
  unsigned int  free_context : 1;     /**< Must free context on shutdown */
#endif
};

/**
 * Representation of the internal state of SSPI NTLM implementation.
 * Because we have no control over the internal state of NTLM SSP,
 * we can't just return FALSE in case of out-of-memory errors and
 * then expect to re-run the function later. We need to remember
 * which state the SSP is in, to avoid calling SSPI functions
 * multiple times with the same arguments, which will lead to an error.
 */
typedef enum
{
  DBUS_SSPI_NTLM_INTERNAL_STATE_CLEAN,
  DBUS_SSPI_NTLM_INTERNAL_STATE_SEND_ERROR,
  DBUS_SSPI_NTLM_INTERNAL_STATE_SEND_REJECTED,
  DBUS_SSPI_NTLM_INTERNAL_STATE_SEND_CHALLENGE,
  DBUS_SSPI_NTLM_INTERNAL_STATE_SERVER_DATA_CHECK_IF_DONE,
  DBUS_SSPI_NTLM_INTERNAL_STATE_SERVER_DATA_GET_NEXT_CHALLENGE,
  DBUS_SSPI_NTLM_INTERNAL_STATE_SERVER_DATA_MAYBE_SEND_CHALLENGE,
  DBUS_SSPI_NTLM_INTERNAL_STATE_SERVER_DATA_FETCH_CREDENTIALS,
  DBUS_SSPI_NTLM_INTERNAL_STATE_SERVER_DATA_SEND_OK,
  DBUS_SSPI_NTLM_INTERNAL_STATE_SEND_RESPONSE,
  DBUS_SSPI_NTLM_INTERNAL_STATE_CLIENT_DATA_GET_NEXT_RESPONSE,
  DBUS_SSPI_NTLM_INTERNAL_STATE_CLIENT_DATA_MAYBE_SEND_RESPONSE,
  DBUS_SSPI_NTLM_INTERNAL_STATE_INVALID = -1
} DBusSSPINTLMInternalState;


void _dbus_win_set_error_from_sspi_status (DBusError       *error,
                                           const char      *func_call,
                                           SECURITY_STATUS  status);
void _dbus_win_warn_sspi_status           (const char      *message,
                                           const char      *func_call,
                                           SECURITY_STATUS  status);

dbus_bool_t _dbus_sspi_ntlm_next_challenge    (DBusSSPINTLMInfo          *sspi_ntlm,
                                               DBusSSPINTLMInternalState *state,
                                               const DBusString          *data,
                                               DBusString                *challenge,
                                               dbus_bool_t               *done,
                                               dbus_bool_t               *error_is_local,
                                               DBusError                 *error);

dbus_bool_t _dbus_sspi_ntlm_fetch_credentials (DBusSSPINTLMInfo          *sspi_ntlm,
                                               DBusSSPINTLMInternalState *state,
                                               DBusCredentials           *credentials,
                                               dbus_bool_t               *error_is_local,
                                               DBusError                 *error);

dbus_bool_t _dbus_sspi_ntlm_initial_response  (DBusSSPINTLMInfo          *sspi_ntlm,
                                               DBusSSPINTLMInternalState *state,
                                               DBusString                *initial_response,
                                               DBusError                 *error);

dbus_bool_t _dbus_sspi_ntlm_next_response     (DBusSSPINTLMInfo          *sspi_ntlm,
                                               DBusSSPINTLMInternalState *state,
                                               const DBusString          *data,
                                               DBusString                *response,
                                               dbus_bool_t               *error_is_local,
                                               DBusError                 *error);

void        _dbus_sspi_ntlm_free_info         (DBusSSPINTLMInfo *sspi_ntlm);


HANDLE      _dbus_spawn_program (const char *name,
                                 char **argv,
                                 char **envp,
                                 dbus_bool_t inherit_handles,
                                 DBusError *error);

DBUS_PRIVATE_EXPORT
void _dbus_win_set_error_from_last_error (DBusError  *error,
                                          const char *format,
                                          ...) _DBUS_GNUC_PRINTF (2, 3);

DBUS_PRIVATE_EXPORT
HANDLE _dbus_win_event_create_inheritable (DBusError *error);
DBUS_PRIVATE_EXPORT
dbus_bool_t _dbus_win_event_set (HANDLE handle, DBusError *error);
DBUS_PRIVATE_EXPORT
dbus_bool_t _dbus_win_event_wait (HANDLE handle, int timeout, DBusError *error);
DBUS_PRIVATE_EXPORT
dbus_bool_t _dbus_win_event_free (HANDLE handle, DBusError *error);

dbus_bool_t _dbus_daemon_is_session_bus_address_published (const char *scope);
dbus_bool_t _dbus_daemon_publish_session_bus_address (const char *address,
                                                      const char *shm_name);
DBUS_PRIVATE_EXPORT
DBusRMutex  *_dbus_win_rmutex_named_new (const char* name);

DBUS_PRIVATE_EXPORT
void _dbus_test_win_autolaunch_set_command_line_parameter (const char *path);
DBUS_PRIVATE_EXPORT
void _dbus_test_win_set_autolaunch_handle_location (HANDLE *location);
#endif

/** @} end of sysdeps-win.h */
