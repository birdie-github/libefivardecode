# SPDX-License-Identifier: LGPL-2.1-or-later
"""Compare independent parsers on generated payloads. See README for invocation."""
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import UUID

exe, registry, oracle = sys.argv[1:]
guid = '8be4df61-93ca-11d2-aa0d-00e098032b8c'


def child(node, name):
    return next(v for v in node['children'] if v['field'] == name)


with tempfile.TemporaryDirectory() as tmp:
    path = Path(tmp)/'payload'

    def pair(kind, name, payload):
        path.write_bytes(payload)
        cli = subprocess.check_output([exe, '--registry-dir', registry, '--no-user-registry',
            '--payload', str(path), '--name', name, '--attrs', '7', '--guid', guid, '--json'])
        expected = subprocess.check_output([oracle, kind, str(path)])
        return json.loads(cli)[0]['value'], json.loads(expected)

    blob = struct.pack('<IH', 1, 4) + 'Fixture\0'.encode('utf-16le') + bytes.fromhex('7fff040001ab')
    node, expected = pair('boot', 'Boot9999', blob)
    assert [child(node,'attributes')['number'], child(node,'description')['text'],
            child(node,'optional_data')['hex'].lower()] == expected

    typ = UUID('c1c41626-504c-4092-aca9-41f936934328')
    owner = UUID('00000000-0000-0000-0000-000000000001')
    blob = typ.bytes_le + struct.pack('<III', 76, 0, 48) + owner.bytes_le + bytes(range(32))
    node, expected = pair('db', 'KEK', blob)
    actual = [[child(group,'signature_type')['text'], child(entry,'owner')['text'],
               child(entry,'data')['hex'].lower()] for group in node['children']
              for entry in child(group,'entries')['children']]
    assert actual == expected
