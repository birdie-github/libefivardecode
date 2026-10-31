// SPDX-License-Identifier: LGPL-2.1-or-later
#include <efivar/efivar.h>
#include <string.h>
// The caller has checked the type, subtype and exact fixed length.
int evd_format_fixed_node(const uint8_t *node,size_t length,char *text,size_t capacity)
{
    union { uint64_t alignment; uint8_t data[16]; } buffer = {0};
    const uint8_t end[] = {0x7f,0xff,4,0};
    if (length > sizeof(buffer.data)-sizeof(end)) return 0;
    memcpy(buffer.data,node,length);
    memcpy(buffer.data+length,end,sizeof(end));
    ssize_t count=efidp_format_device_path((unsigned char *)text,capacity,
                                           (const_efidp)buffer.data,length+sizeof(end));
    return count>0 && (size_t)count<=capacity && memchr(text,0,capacity)!=NULL;
}
