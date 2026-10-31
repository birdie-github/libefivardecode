# SPDX-License-Identifier: LGPL-2.1-or-later
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import UUID

exe, registry = sys.argv[1:]
global_guid = '8be4df61-93ca-11d2-aa0d-00e098032b8c'
security_guid = 'd719b2cb-3d3a-4596-a3bc-dad00e67656f'
vendor_guid = 'c89dc9c7-5105-472c-a743-b1621e142b41'
end = bytes.fromhex('7f ff 04 00')


def option(label):
    return struct.pack('<IH', 1, len(end)) + (label+'\0').encode('utf-16le') + end


def check(args, code=0):
    p = subprocess.run([exe, '--registry-dir', registry, '--no-user-registry', *args],
                       text=True, capture_output=True)
    assert p.returncode == code, (args, p.returncode, p.stdout, p.stderr)
    return p.stdout


with tempfile.TemporaryDirectory() as tmp:
    base = Path(tmp)
    snap = base/'snapshot'
    snap.mkdir()

    def put(name, data, guid=global_guid, attrs=7):
        path = snap/(name+'-'+guid)
        path.write_bytes(struct.pack('<I', attrs)+data)
        return path

    def one(name, code=0, extra=()):
        return json.loads(check(['--efivarfs-dir', str(snap), '--name', name,
                                 '--json', *extra], code))[0]

    put('BootCurrent', b'\x02\x00', attrs=6)
    for label in ('Fedora', 'Different installation'):
        target = put('Boot0002', option(label))
        assert one('BootCurrent')['value']['text'] == 'Boot0002 — '+label
    target.unlink()
    reference = one('BootCurrent')['value']
    assert reference['text'] == 'Boot0002' and reference['children'][-1]['text'] == 'missing'
    put('Boot0002', b'\0')
    assert one('BootCurrent')['value']['children'][-1]['text'] == 'target_malformed'
    put('Timeout', b'\1\0')
    assert '1 second' in check(['--efivarfs-dir', str(snap), '--name', 'Timeout'])
    put('Timeout', b'\xff\xff')
    assert one('Timeout')['value']['text'] == 'Wait for user input'
    put('CMOSfailflag', b'\x08\x00', vendor_guid)
    row = one('CMOSfailflag')
    assert row['status'] == 'unknown' and row['value']['hex'] == '0800'
    for name in ('boot0002', 'Boot00a2', 'Boot99999', 'dbGuess'):
        put(name, b'\1')
        assert one(name)['status'] == 'unknown'
    put('Timeout', b'\1', vendor_guid)
    assert one('Timeout', extra=['--guid', vendor_guid])['status'] == 'unknown'
    check(['--efivarfs-dir', str(snap), '--name', 'Timeout'], 1)
    put('SecureBoot', b'\2')
    assert one('SecureBoot')['value']['children'][0]['text'] == 'reserved'
    put('BootOptionSupport', struct.pack('<I', 0x80000313))
    fields = one('BootOptionSupport')['value']['children']
    assert {f['field']: f['number'] for f in fields}['unknown_bits'] == 0x80000000
    assert any(f['field']=='maximum_key_count' and f['number']==3 for f in fields)
    put('BootOrder', b'\x99\x99\x01')
    assert one('BootOrder', 2)['error_offset'] == 2

    payload = base/'payload'

    def decode(name, data, guid=global_guid, code=0):
        payload.write_bytes(data)
        return json.loads(check(['--payload', str(payload), '--guid', guid, '--name', name,
                                 '--attrs', '6', '--json'], code))[0]

    blob = option('Example')
    assert decode('Boot9999', blob)['status'] == 'ok'
    for cut in range(len(blob)):
        assert decode('Boot9999', blob[:cut], code=2)['status'] == 'malformed'
    for malformed in (b'\x04\x04\0\0', b'\x7f\xff\x05\0\0', end+b'x'):
        assert decode('ConIn', malformed, code=2)['status'] == 'malformed'

    # Unknown signature type with a nonempty header and two original entries.
    typ = UUID('10000000-0000-0000-0000-000000000001').bytes_le
    entry = bytes(16) + b'AB'
    db = typ + struct.pack('<III', 28+1+2*len(entry), 1, len(entry)) + b'H' + entry*2
    nodes = decode('db', db, security_guid)['value']['children'][0]['children']
    assert nodes[0]['text'] == str(UUID(bytes_le=typ))
    assert len(nodes[-1]['children'])==2
    for cut in range(1,len(db)):
        assert decode('db', db[:cut], security_guid, 2)['status']=='malformed'
    users = base/'overrides'
    users.mkdir()
    rule = dict(name='CMOSfailflag', meaning='Synthetic test override', format='u16le')
    doc = dict(schema=1, guid=vendor_guid, source='Synthetic fixture', rules=[rule])
    (users/'test.json').write_text(json.dumps(doc))
    custom = one('CMOSfailflag', extra=['--user-registry-dir',str(users)])
    assert custom['user_rule'] and custom['value']['number']==8
    doc['rules'].append(rule)
    (users/'test.json').write_text(json.dumps(doc))
    check(['--efivarfs-dir',str(snap),'--user-registry-dir',str(users)],1)
