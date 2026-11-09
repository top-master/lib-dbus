# dbus security

dbus does not come with any guarantee of security,
and its maintainers are not suppliers of a finished product.
Please see the applicable licenses (in the `LICENSES/` directory)
for more details.
If a system integrator has chosen to rely on dbus as part of a product,
service or larger system,
the system integrator is responsible for that decision.

The maintainers of dbus try to address security vulnerabilities when
it is feasible to do so,
within the limits of available time and resources.

## Reporting security vulnerabilities

If you find a security vulnerability that is not known to the public,
please report it privately to <dbus-security@lists.freedesktop.org>,
or by reporting a Gitlab issue at
<https://gitlab.freedesktop.org/dbus/dbus/-/work_items/new>
and marking it as "confidential".

If you are unsure whether a bug is a security vulnerability or not,
please report it as confidential.

Proposed fixes can be attached to the issue using the output of
`git format-patch`.

**Please do not create a merge request for undisclosed security vulnerabilities,
or push proposed changes fixing an undisclosed security vulnerability
to any public location.**

## CVE IDs

If you allocate a CVE ID or similar unique identifier for a vulnerability,
please leave a comment with the CVE ID on the relevant issue report,
or create a new issue report if necessary
(marked as confidential if the vulnerability is not yet known to the public).
The dbus maintainers cannot provide support for CVE IDs that are allocated
without their knowledge.

## Scope

### dbus-daemon

On Unix systems, the [system bus][] (`dbus-daemon --system`) is designed
to be a security boundary between users with different privileges.

On Unix systems, the [session bus][] (`dbus-daemon --session`) is designed
to be used by a single user, and only accessible by that user.
Any user who can connect to the session bus,
without their access being filtered through a restrictive proxy such as
[`xdg-dbus-proxy`][xdg-dbus-proxy],
should be assumed to have all the privileges of any other process
connected to the session bus.

If another system component or an OS vendor or sysadmin provides "drop-in"
XML configuration in `system.d` or `session.d`,
then the author of that configuration file is responsible for ensuring that
it does not introduce security vulnerabilities.
Implementors should be aware that the XML configuration language is
not straightforward,
and some `<allow>` and `<deny>` rules can have unexpected effects.
The dbus source code is the only authoritative reference for how the
policy language works.

`dbus-daemon` can also be used to implement custom buses such as the
AT-SPI accessibility bus.
The authors of the XML configuration files used to define these buses are
responsible for securing them appropriately.

[session bus]: https://dbus.freedesktop.org/doc/dbus-specification.html#message-bus-types-login
[system bus]: https://dbus.freedesktop.org/doc/dbus-specification.html#message-bus-types-system
[xdg-dbus-proxy]: https://github.com/flatpak/xdg-dbus-proxy

### libdbus

libdbus aims to be a suitable client library for connecting to the
well-known system message bus,
the well-known session message bus,
and other buses with similar security characteristics.
The client address must be obtained from a trustworthy source:
if a program can be induced to connect to an attacker-chosen address,
then that should be assumed to be a vulnerability in the program,
not libdbus.

libdbus also aims to be a suitable library for implementing custom servers
using `DBusServer`.
If it is used in this way,
the API user is responsible for securing the server appropriately,
including enforcing whatever form of access control matches their
security requirements,
and disabling authentication mechanisms that are inappropriate for their
security requirements.

libdbus is not intended to be safe for use by programs that have higher
privileges than their parent process,
such as setuid executables.
Programs with elevated privileges are expected to clear their
attacker-supplied environment variables (`environ`),
applying a default-deny filter to variables and their values,
before calling into libdbus.

### Denial of service

dbus makes an attempt to avoid trivial denial-of-service issues,
but should not be relied on to be resistant to denial-of-service
via resource exhaustion,
especially on systems with actively malicious local users.

### Operating systems

From a security point of view,
dbus is primarily maintained for GNU/Linux.

dbus aims to be portable to other Unix operating systems such as FreeBSD,
but maintainers do not routinely test on non-Linux operating systems and
OS-specific issues for non-Linux operating systems are likely to be treated
as a lower priority.

dbus is also portable to Windows,
but we do not currently consider dbus on Windows to be security-supported.

### Authentication mechanisms

Contexts where dbus is acting as a security boundary should use the
`EXTERNAL` authentication mechanism.

The `DBUS_COOKIE_SHA1` authentication mechanism is not recommended.

The `ANONYMOUS` authentication mechanism does not provide any security
and cannot be used where a security boundary is expected.

`dbus-daemon` instances where a security boundary is required should use
`<auth>EXTERNAL</auth>` to disable use of any other authentication mechanism.
`DBusServer` instances where a security boundary is required should call:

```c
const char *only_external[] = { "EXTERNAL", NULL };
dbus_server_set_auth_mechanisms(server, only_external);
```

### TCP transports

The `tcp:` and `nonce-tcp:` transports are based on TCP streams,
without any integrity or confidentiality protection:
they should be assumed to have security characteristics similar to
unencrypted HTTP.

The TCP-based transports are provided for compatibility with older
versions of Windows that did not implement `AF_UNIX` sockets.
They should not be used on Unix systems.

These TCP-based transports do not defend against denial of service
by local users, and therefore should not be used on multi-user systems.

### Assertions, intrusive tests and other instrumentation

dbus can be compiled with assertions
(`meson setup -Dasserts=true` or `cmake -DDBUS_DISABLE_ASSERT=OFF`)
and/or with "intrusive tests" enabled
(`meson setup -Dintrusive_tests=true` or
`cmake -DDBUS_ENABLE_INTRUSIVE_TESTS=ON`).
Both of these insert extra instrumentation into libdbus and the dbus-daemon
to detect situations that should have been impossible and provide better
test coverage,
but this instrumentation adds extra code and is a security risk.

A production version of dbus that will be included in an operating system
or other product should never have the intrusive tests enabled.
Similarly,
a production version of dbus should not enable other forms of
instrumentation such as coverage recording or AddressSanitizer.

Similarly,
enabling assertions in a production version of dbus is not recommended,
and distributors should be aware that a version of dbus with assertions
enabled will be more susceptible to denial-of-service.

Developers may enable these instrumentation features for debugging and
testing,
and they can be used to make security vulnerabilities easier to reproduce,
but if there is a bug that is only exploitable when compiled with these
instrumentation features,
it will not be considered to be a security vulnerability.
