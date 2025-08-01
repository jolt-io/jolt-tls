# Jolt TLS

![GitHub License](https://img.shields.io/github/license/jolt-io/jolt-tls?color=orange)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/jolt-io/jolt-tls/test-x86_64-linux.yml?label=x86_64-linux)

Tiny yet vigorous asynchronous TLS module 🍋. Jolt TLS offers a convenient way to have TLS streams in Jolt.

## Features

* Supports TLS 1.2 and TLS 1.3
* Fully asynchronous and evented design
* Uses [BoringSSL](https://boringssl.googlesource.com/boringssl) for efficient TLS streams
* Predictable memory usage
* Small number of copies

## Future Plans

- [ ] TLS Server
- [ ] Support for more TLS modules (namely [tls.zig](https://github.com/ianic/tls.zig), [mbedtls](https://github.com/Mbed-TLS/mbedtls))
- [ ] Support for native Windows TLS ([Schannel](https://learn.microsoft.com/en-us/windows/win32/secauthn/creating-a-secure-connection-using-schannel))
- [ ] Certificate compression ([RFC 8879](https://www.rfc-editor.org/rfc/rfc8879.html))
