# libefivardecode

A read-only UEFI variable decoder with a C ABI. A caller supplies an original
variable name, namespace GUID, attributes and payload from memory. An installed
JSON registry describes variable meanings. The decoder returns an owned tree
with numeric values, strings, byte ranges, provenance and diagnostics.
The CLI also reads Linux efivarfs directories, including offline copies.

## Build

Requires CMake 3.16+, a C++17 compiler, pkg-config and Jansson 2.14 or later.
The public header is usable from C11 and C++. On Fedora the Jansson development
package is `jansson-devel`. The optional device path formatter uses
`efivar-devel`. The core has no dependency on Qt, kernel headers or a running
EFI system. The ABI version for the 0.1 series is 0.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
cmake --install build
```

The install prefix defaults to /usr/local on Unix. Set CMAKE_INSTALL_PREFIX
at configure time to change the compiled-in registry location. A staging
DESTDIR does not become part of that location. Applications can link with
`pkg-config --libs --cflags libefivardecode`. All JSON implementation types
and C++ types stay private.

## CLI

```sh
efivardecode --efivarfs-dir ./efivars --name BootCurrent
efivardecode --efivarfs-dir /sys/firmware/efi/efivars --json
efivardecode --efivarfs-dir ./efivars --name db --verbose
efivardecode --payload timeout.bin --name Timeout \
  --guid 8be4df61-93ca-11d2-aa0d-00e098032b8c --attrs 0x7
```

Shipped rules are embedded in both static and shared builds. Optional system
registry files override built-ins, and user files take precedence over both. Directory input
strips the four-byte little-endian efivarfs header and indexes exact names and
GUIDs before decoding. A name shared by two namespaces needs a GUID filter.
Single-variable input takes the payload after that header. Decimal and 0x
attribute masks are accepted. Directory input does not follow symbolic links.

Text output summarizes large byte strings and signature lists. Use --verbose
for nested fields or --json for complete byte fields. JSON emits an array,
including for a single result. Unsigned integers are JSON numbers up to
UINT64_MAX. Consumers using IEEE doubles should select a lossless JSON
reader when exact 64-bit values matter. Exit status 0 means successful
inspection (unknown variables are allowed), 2 means a malformed known value
was found, and 1 reports argument, input, registry or resource errors.

## Memory API

```c
#include <efivardecode.h>
#include <stdio.h>

int inspect_timeout(void)
{
    evd_registry *registry = evd_registry_open(NULL, "");
    if (!registry) return 1;
    const uint8_t bytes[] = {1, 0};
    evd_input in = {"Timeout", "8be4df61-93ca-11d2-aa0d-00e098032b8c",
                    7, bytes, sizeof(bytes)};
    evd_result *result = evd_decode(registry, &in, NULL, NULL);
    evd_registry_free(registry);
    if (!result) return 1;
    if (evd_result_status(result) == EVD_OK) {
        const evd_node *root = evd_root(result);
        printf("%llu %s\n", (unsigned long long)evd_uint(root), evd_unit(root));
    }
    evd_result_free(result);
    return 0;
}
```

Registry handles are immutable after construction and may be shared across
threads. Pass valid handles to accessors. A result owns its metadata, node
strings and original payload. Child pointers and raw spans remain valid until
the result is freed. Match children by field identifier. Repeated identifiers
in a list preserve wire order and duplicates. An implicit field derived
from a name or external variable attribute has zero payload length.
Annotations of payload fields refer to the source field's byte range.

Unknown variables keep their bytes. A malformed known value retains its
original payload, parsed prefix, diagnostic and offset. A reserved enum adds
a `value_status` child; a bitmask preserves unrecognized set bits in
`unknown_bits`. Both retain the complete numeric value. The enclosing
variable attributes and the attributes inside a boot load option have
different accessors and definitions. A null result indicates an API or
resource error; `evd_error()` gives the thread-local message. Each decode
allows up to 262144 child-node creations, including resolved targets.

To resolve boot references, pass an evd_lookup function and your snapshot as
its context. Return 1 and a borrowed payload on success, 0 for a missing entry,
or -1 for a lookup failure. Target bytes must stay valid until decode returns.
The reference node carries the option number, target_guid, target_name and
resolution, and a target_label when resolved. No host lookup occurs. A target
with invalid framing reports target_malformed independently of the source
status. Load-option optional data and unknown device-path node bodies remain
available as bytes.

## Extending the registry

Definitions are in `share/libefivardecode/registry.d/*.json`. Per-user files
go in `$XDG_CONFIG_HOME/libefivardecode/registry.d/` (default
`~/.config/libefivardecode/registry.d/`). Both directories are configurable.
Use an empty user directory argument or --no-user-registry for reproducibility.
A missing default user directory is fine. A missing or empty system registry
is an initialization error. Reopen the registry after editing.

For example, this is a complete file that changes the display of Timeout:

```json
{
  "schema": 1,
  "guid": "8be4df61-93ca-11d2-aa0d-00e098032b8c",
  "source": "https://uefi.org/specs/UEFI/2.11/03_Boot_Manager.html",
  "rules": [
    {
      "name": "Timeout",
      "meaning": "Boot menu timeout",
      "format": "u16le",
      "unit": "second",
      "special": { "0": "Start immediately", "65535": "Wait for input" }
    }
  ]
}
```

A user rule replaces the complete shipped rule for that selector. Source can
be overridden per rule. GUIDs are normalized, names are matched literally, and
exact names precede families. A family ending in #### consumes exactly four
uppercase hex digits. The special linux-pstore selector matches the modern
numeric kernel record filename grammar including the compression marker.
Legacy filename layouts fall back to raw. Files are processed lexically, but
two definitions for one selector within the same layer are rejected. There is
no executable expression language.

* Scalar formats are u8, u16le, u32le and u64le. The maps enum and special
  have decimal integer keys. Set otherwise to reserved for a closed enum.
  A bits map names individual bit positions. A fields array describes masked
  integers using lsb, width, name and optional unit.
* u16le[] and guid[] preserve element order. A u16le or u16le[] reference can
  name a same-GUID load-option family. See BootCurrent and BootOrder.
* ascii-z and utf16-z require a terminator. languages splits a terminated
  ASCII language list. uuid-text validates a UTF-16 UUID. sbat-lines preserves
  rows without evaluating revocation policy.
* efi-load-option, device-path and signature-list walk binary structures.
  pstore exposes filename metadata and compressed or uncompressed bytes.
  raw attaches a documented meaning without asserting any internal layout.
* guid_labels supplies display names independently of variable names.
  signature_data_bytes defines known fixed-width signature bodies, excluding
  the owner GUID. Unknown types retain their on-disk GUID and entry data.
  Shared variable_attributes and load_option_attributes layouts use the same
  bit and integer-field syntax as variable rules.

For richer PCI, USB and SATA node text, configure with -DEVD_RHBOOT=ON.
Only nodes with known fixed widths are passed to the optional formatter.
The portable build understands device-path instance and end nodes, hard-drive
nodes and UTF-16 file paths. Certificate bytes are exposed without parsing
DER, validating trust chains or interpreting vendor policy. The base release
has no firmware write interface.

## Additional developer checks

CTest includes a C ABI/ownership test and, when Python 3 is available, synthetic
CLI and registry tests. No real firmware snapshot is needed.

For an optional differential check against Canonical's Go implementation:

```sh
(cd tests/oracle && go build -mod=mod -o ../../build/evd-oracle .)
python3 tests/differential.py ./build/efivardecode ./registry ./build/evd-oracle
```

With Clang and libFuzzer:

```sh
CC=clang CXX=clang++ cmake -S . -B fuzz -DEVD_FUZZ=ON -DBUILD_TESTING=OFF
cmake --build fuzz -j
mkdir -p fuzz/corpus
./fuzz/evd_fuzz -max_len=65536 -max_total_time=60 fuzz/corpus
```

## License

SPDX-License-Identifier: LGPL-2.1-or-later. See LICENSE.
