// SPDX-License-Identifier: LGPL-2.1-or-later
#include "internal.hpp"
#include <array>
#include <cstdio>
#ifdef EVD_RHBOOT
extern "C" int evd_format_fixed_node(const uint8_t *,size_t,char *,size_t);
#endif
string wire_guid(Span s) {
    s.sub(0,16);
    constexpr unsigned order[]={3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
    constexpr char hex[]="0123456789abcdef";
    string out;
    for (unsigned i=0;i<16;++i) {
        if (i==4||i==6||i==8||i==10) out+='-';
        auto b=s.p[order[i]]; out+=hex[b>>4]; out+=hex[b&15];
    }
    return out;
}
string utf16(Span s) {
    string out;
    for (size_t i=0;i<s.n;i+=2) {
        unsigned c=unsigned(s.le(i,2));
        if (!c) {
            if (i+2!=s.n) throw Bad{s.off+i,"unexpected interior NUL"};
            return out;
        }
        if (c>=0xd800 && c<=0xdbff) {
            i+=2; unsigned d=unsigned(s.le(i,2));
            if (d<0xdc00||d>0xdfff) throw Bad{s.off+i,"invalid UTF-16 surrogate"};
            c=0x10000+((c-0xd800)<<10)+(d-0xdc00);
        } else if (c>=0xdc00 && c<=0xdfff) throw Bad{s.off+i,"unpaired UTF-16 surrogate"};
        if (c<128) out+=char(c);
        else {
            if (c>=0x10000) { out+=char(0xf0|(c>>18)); out+=char(0x80|((c>>12)&63)); }
            else if (c>=0x800) out+=char(0xe0|(c>>12));
            else out+=char(0xc0|(c>>6));
            if (c>=0x800) out+=char(0x80|((c>>6)&63));
            out+=char(0x80|(c&63));
        }
    }
    throw Bad{s.off+s.n,"missing UTF-16 terminator"};
}
namespace {
void number(evd_node &n,const char *field,Span s,size_t pos,size_t width) {
    auto part=s.sub(pos,width);
    n.add(EVD_UINT,field,part).number=part.le(0,width);
}
size_t path(evd_node &out,Span s) {
    size_t pos=0;
    while (pos<s.n) {
        auto len=size_t(s.le(pos+2,2));
        if (len<4) throw Bad{s.off+pos+2,"device path node shorter than header"};
        auto d=s.sub(pos,len);
        auto &n=out.add(EVD_RECORD,"node",d);
        number(n,"type",d,0,1); number(n,"subtype",d,1,1);
        auto type=d.p[0],sub=d.p[1];
        if (type==0x7f) {
            if (len!=4 || (sub!=1 && sub!=255)) throw Bad{d.off,"invalid end node"};
            if (sub==255) return pos+len;
        } else if (type==4 && sub==4) {
            auto text=d.sub(4,len-4);
            n.add(EVD_TEXT,"path",text).text=utf16(text);
        } else if (type==4 && sub==1) {
            if (len!=42) throw Bad{d.off,"invalid hard drive node length"};
            number(n,"partition",d,4,4); number(n,"start_lba",d,8,8); number(n,"size_lba",d,16,8);
            number(n,"partition_format",d,40,1); number(n,"signature_type",d,41,1);
            auto sig=d.sub(24,16);
            if (d.p[41]==2) n.add(EVD_GUID,"partition_guid",sig).text=wire_guid(sig);
            else n.add(EVD_BYTES,"signature",sig);
        } else {
            n.add(EVD_BYTES,"body",d.sub(4,len-4));
#ifdef EVD_RHBOOT
            // Only fixed-width nodes whose entire layout was size-checked.
            if ((type==1 && sub==1 && len==6) || (type==3 && sub==5 && len==6) ||
                (type==3 && sub==18 && len==10)) {
                char text[128]{};
                if (evd_format_fixed_node(d.p,len,text,sizeof(text))) n.text=text;
            }
#endif
        }
        pos+=len;
    }
    throw Bad{s.off+pos,"missing end-of-device-path node"};
}
}
void device_path(evd_node &out,Span s) {
    out.kind=EVD_LIST;
    size_t used=path(out,s);
    if (used!=s.n) throw Bad{s.off+used,"data after end of device path"};
}
void load_option(evd_node &out,Span s) {
    out.kind=EVD_RECORD;
    number(out,"attributes",s,0,4); number(out,"path_list_length",s,4,2);
    size_t pos=6;
    while (s.le(pos,2)!=0) pos+=2;
    pos+=2;
    auto desc=s.sub(6,pos-6);
    out.add(EVD_TEXT,"description",desc).text=utf16(desc);
    auto paths=s.sub(pos,size_t(s.le(4,2)));
    auto &list=out.add(EVD_LIST,"paths",paths);
    for (size_t i=0;i<paths.n;) {
        auto rest=paths.sub(i,paths.n-i);
        auto &one=list.add(EVD_LIST,"device_path",rest);
        one.length=path(one,rest); i+=one.length;
    }
    pos+=paths.n; out.add(EVD_BYTES,"optional_data",s.sub(pos,s.n-pos));
}
void signatures(evd_node &out,Span s,const evd_registry &reg) {
    out.kind=EVD_LIST;
    for (size_t pos=0;pos<s.n;) {
        auto len=size_t(s.le(pos+16,4));
        auto d=s.sub(pos,len);
        d.sub(0,28);
        auto h=size_t(d.le(20,4)), stride=size_t(d.le(24,4));
        auto header=d.sub(28,h);
        if (stride<16 || (d.n-28-h)%stride) throw Bad{d.off+24,"invalid signature entry size"};
        auto &list=out.add(EVD_RECORD,"signature_list",d);
        auto id=d.sub(0,16); string type=wire_guid(id);
        auto expected=reg.signature_sizes.find(type);
        if (expected!=reg.signature_sizes.end() && stride-16!=expected->second)
            throw Bad{d.off+24,"wrong entry size for signature type"};
        auto &guid=list.add(EVD_GUID,"signature_type",id); guid.text=type;
        auto label=reg.aliases.find(type);
        if (label!=reg.aliases.end()) guid.add(EVD_TEXT,"label",id).text=label->second;
        number(list,"list_size",d,16,4); number(list,"header_size",d,20,4);
        number(list,"signature_size",d,24,4);
        list.add(EVD_BYTES,"header",header);
        auto entries=d.sub(28+h,d.n-28-h);
        auto &items=list.add(EVD_LIST,"entries",entries);
        for (size_t i=0;i<entries.n;i+=stride) {
            auto e=entries.sub(i,stride);
            auto &item=items.add(EVD_RECORD,"signature",e);
            item.add(EVD_GUID,"owner",e.sub(0,16)).text=wire_guid(e);
            item.add(EVD_BYTES,"data",e.sub(16,stride-16));
        }
        pos+=len;
    }
}
bool pstore_name(const string &s,evd_node *out) {
    if (s.compare(0,9,"dump-type")!=0) return false;
    const char *p=s.data()+9,*end=s.data()+s.size();
    std::array<uint64_t,4> values{};
    for (auto &v:values) {
        auto r=std::from_chars(p,end,v);
        if (r.ec!=std::errc{} || r.ptr==end || *r.ptr!='-') return false;
        p=r.ptr+1;
    }
    if (end-p!=1 || (*p!='C' && *p!='D') || values[0]>UINT32_MAX ||
        values[1]>UINT32_MAX || values[2]>INT32_MAX) return false;
    if (out) {
        const char *keys[]={"record_type","part","count","timestamp"};
        for (size_t i=0;i<4;++i) out->add(EVD_UINT,keys[i],{nullptr,0,0}).number=values[i];
        out->add(EVD_UINT,"compressed",{nullptr,0,0}).number=*p=='C';
    }
    return true;
}
