// SPDX-License-Identifier: LGPL-2.1-or-later
#include "internal.hpp"
#include <algorithm>
#include <cstdio>
namespace {
// A fixed buffer also keeps allocation failure from escaping the C boundary.
thread_local char last_error[1024];
void fail(const char *s) noexcept { std::snprintf(last_error,sizeof(last_error),"%s",s); }
void annotate(evd_node &n,Span s,const Rule &r,uint64_t value) {
    n.kind=EVD_UINT; n.number=value; n.unit=r.unit;
    auto it=r.labels.find(n.number);
    if (it!=r.labels.end()) n.text=it->second;
    else if (r.reserved) n.add(EVD_TEXT,"value_status",s).text="reserved";
    uint64_t remaining=n.number;
    for (auto &b:r.bits) {
        auto mask=uint64_t(1)<<b.first;
        if (n.number&mask) {
            auto &flag=n.add(EVD_UINT,"set_bit",s); flag.number=b.first; flag.text=b.second;
        }
        remaining &= ~mask;
    }
    for (auto &f:r.fields) {
        uint64_t mask=UINT64_MAX>>(64-f.width);
        auto &field=n.add(EVD_UINT,f.name,s);
        field.number=(n.number>>f.lsb)&mask; field.unit=f.unit;
        remaining &= ~(mask<<f.lsb);
    }
    if (remaining && (!r.bits.empty()||!r.fields.empty()))
        n.add(EVD_UINT,"unknown_bits",s).number=remaining;
}
void reference(evd_node &n,Span s,const Rule &r,const evd_registry &reg,evd_lookup lookup,void *ctx) {
    n.kind=EVD_REFERENCE; n.number=s.le(0,2);
    char suffix[5]; std::snprintf(suffix,sizeof(suffix),"%04X",unsigned(n.number));
    string target=r.target.substr(0,r.target.size()-4)+suffix;
    n.text=target;
    n.add(EVD_GUID,"target_guid",s).text=r.guid;
    n.add(EVD_TEXT,"target_name",s).text=target;
    string state="not_looked_up";
    if (lookup) {
        const uint8_t *p=nullptr; size_t len=0;
        int found=lookup(ctx,r.guid.c_str(),target.c_str(),&p,&len);
        auto rule=reg.find(r.guid,target);
        if (found==0) state="missing";
        else if (found!=1 || (!p && len)) state="unavailable";
        else if (!rule || rule->format!="efi-load-option") state="unsupported_target";
        else {
            try {
                evd_node entry(EVD_RECORD,"target",{p,len,0}); load_option(entry,{p,len,0});
                for (const auto &field:entry.children) if (field.field=="description") {
                    n.add(EVD_TEXT,"target_label",s).text=field.text;
                    if (!field.text.empty()) n.text+=" — "+field.text;
                }
                state="resolved";
            } catch (const Bad &) { state="target_malformed"; }
        }
    }
    n.add(EVD_TEXT,"resolution",s).text=state;
}
void ascii(evd_node &n,Span s,const string &format) {
    bool lines=format=="sbat-lines", list=lines || format=="languages";
    size_t end=s.n;
    if (!lines) {
        if (!end || s.p[end-1]) throw Bad{s.off+end,"missing ASCII terminator"};
        --end;
    } else if (end && s.p[end-1]==0) --end;
    for (size_t i=0;i<end;++i)
        if (!s.p[i] || s.p[i]>127) throw Bad{s.off+i,"invalid ASCII byte"};
    if (!list) { n.kind=EVD_TEXT; n.text.assign(reinterpret_cast<const char *>(s.p),end); return; }
    n.kind=EVD_LIST;
    const uint8_t sep=lines?'\n':';';
    for (size_t start=0;start<end;) {
        auto next=std::find(s.p+start,s.p+end,sep);
        size_t len=size_t(next-(s.p+start));
        if (!len) throw Bad{s.off+start,"empty list item"};
        n.add(EVD_TEXT,lines?"row":"language",s.sub(start,len)).text.assign(
            reinterpret_cast<const char *>(s.p+start),len);
        start+=len+1;
        if (!lines && start==end) throw Bad{s.off+end-1,"trailing separator"};
    }
}
void decode(evd_node &n,Span s,const string &name,const Rule &r,const evd_registry &reg,
            evd_lookup lookup,void *ctx) {
    const auto &f=r.format;
    if (f=="raw") return;
    if (f=="efi-load-option") {
        load_option(n,s);
        auto layout=reg.layouts.find("load_option_attributes");
        if (layout!=reg.layouts.end()) annotate(n.children.front(),s.sub(0,4),layout->second,s.le(0,4));
        return;
    }
    if (f=="device-path") return device_path(n,s);
    if (f=="signature-list") return signatures(n,s,reg);
    if (f=="sbat-lines"||f=="languages"||f=="ascii-z") return ascii(n,s,f);
    if (f=="utf16-z"||f=="uuid-text") {
        n.kind=EVD_TEXT; n.text=utf16(s);
        if (f=="uuid-text") {
            try { n.text=canonical_guid(n.text); } catch (const std::runtime_error &) {
                throw Bad{s.off,"invalid UUID string"};
            }
            n.kind=EVD_GUID;
        }
        return;
    }
    if (f=="pstore") {
        n.kind=EVD_RECORD; pstore_name(name,&n); n.add(EVD_BYTES,"data",s); return;
    }
    if (f=="guid[]" || f=="u16le[]") {
        n.kind=EVD_LIST; size_t stride=f=="guid[]"?16:2;
        for (size_t i=0;i<s.n;i+=stride) {
            auto part=s.sub(i,stride); auto &item=n.add(EVD_UINT,"item",part);
            if (stride==16) {
                item.kind=EVD_GUID; item.text=wire_guid(part);
                auto a=reg.aliases.find(item.text);
                if (a!=reg.aliases.end()) item.add(EVD_TEXT,"label",part).text=a->second;
            } else if (!r.target.empty()) reference(item,part,r,reg,lookup,ctx);
            else item.number=part.le(0,2);
        }
        return;
    }
    size_t width=f=="u8"?1:f=="u16le"?2:f=="u32le"?4:8;
    if (s.n!=width) throw Bad{s.off+std::min(s.n,width),"expected exactly "+std::to_string(width)+" bytes"};
    if (r.target.empty()) annotate(n,s,r,s.le(0,s.n));
    else reference(n,s,r,reg,lookup,ctx);
}
}
evd_registry *evd_registry_open(const char *system,const char *user) {
    last_error[0]=0;
    try { auto r=std::make_unique<evd_registry>(); load_registry(*r,system,user); return r.release(); }
    catch (const std::exception &e) { fail(e.what()); return nullptr; }
}
evd_result *evd_decode(const evd_registry *reg,const evd_input *in,evd_lookup lookup,void *ctx) {
    last_error[0]=0;
    try {
        if (!reg||!in||!in->name||!*in->name||!in->guid||(!in->payload&&in->size))
            throw std::invalid_argument("invalid decoder arguments");
        NodeBudget budget;
        auto guid=canonical_guid(in->guid);
        auto out=std::make_unique<evd_result>();
        out->name=in->name; out->guid=guid; out->attrs.number=in->attributes;
        auto layout=reg->layouts.find("variable_attributes");
        if (layout!=reg->layouts.end()) annotate(out->attrs,{nullptr,0,0},layout->second,in->attributes);
        if (in->size) out->payload.assign(in->payload,in->payload+in->size);
        Span s{out->payload.data(),in->size,0};
        out->root.length=s.n;
        auto rule=reg->find(guid,in->name);
        if (!rule) out->status=EVD_UNKNOWN;
        else {
            out->file=rule->file; out->user=rule->user; out->source=rule->source;
            out->selector=rule->selector; out->meaning=rule->meaning;
            try { decode(out->root,s,in->name,*rule,*reg,lookup,ctx); }
            catch (const Bad &e) {
                out->status=EVD_MALFORMED; out->error_offset=e.offset; out->diagnostic=e.reason;
            }
        }
        return out.release();
    } catch (const std::exception &e) { fail(e.what()); return nullptr; }
}
const char *evd_error(void) { return last_error; }
void evd_registry_free(evd_registry *p) { delete p; }
void evd_result_free(evd_result *p) { delete p; }
evd_status evd_result_status(const evd_result *p) { return p->status; }
const char *evd_name(const evd_result *p) { return p->name.c_str(); }
const char *evd_guid(const evd_result *p) { return p->guid.c_str(); }
const evd_node *evd_attributes(const evd_result *p) { return &p->attrs; }
const evd_node *evd_root(const evd_result *p) { return &p->root; }
const uint8_t *evd_payload(const evd_result *p,size_t *n) { if (n) *n=p->payload.size(); return p->payload.data(); }
const char *evd_diagnostic(const evd_result *p) { return p->diagnostic.c_str(); }
size_t evd_error_offset(const evd_result *p) { return p->error_offset; }
const char *evd_rule_file(const evd_result *p) { return p->file.c_str(); }
const char *evd_rule_selector(const evd_result *p) { return p->selector.c_str(); }
const char *evd_source(const evd_result *p) { return p->source.c_str(); }
int evd_user_rule(const evd_result *p) { return p->user; }
const char *evd_meaning(const evd_result *p) { return p->meaning.c_str(); }
evd_kind evd_node_kind(const evd_node *p) { return p->kind; }
const char *evd_field(const evd_node *p) { return p->field.c_str(); }
uint64_t evd_uint(const evd_node *p) { return p->number; }
const char *evd_text(const evd_node *p) { return p->text.c_str(); }
const char *evd_unit(const evd_node *p) { return p->unit.c_str(); }
size_t evd_offset(const evd_node *p) { return p->offset; }
size_t evd_length(const evd_node *p) { return p->length; }
size_t evd_count(const evd_node *p) { return p->children.size(); }
const evd_node *evd_child(const evd_node *p,size_t i) { return i<p->children.size()?&p->children[i]:nullptr; }
