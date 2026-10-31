// SPDX-License-Identifier: LGPL-2.1-or-later
#include "internal.hpp"
#include <algorithm>
#include <cstdlib>
#include <iterator>
using std::runtime_error;
namespace {
using Json = std::unique_ptr<json_t, decltype(&json_decref)>;
void require(bool value,const string &message) { if (!value) throw runtime_error(message); }
void keys(json_t *obj,std::initializer_list<string> allowed) {
    require(json_is_object(obj),"expected object");
    const char *key; json_t *value;
    json_object_foreach(obj,key,value)
        require(std::find(allowed.begin(),allowed.end(),key)!=allowed.end(),"unknown key "+string(key));
}
string str(json_t *value) {
    require(json_is_string(value) && json_string_length(value)>0,"expected nonempty string");
    return json_string_value(value);
}
string prop(json_t *obj,const char *key,bool optional=false) {
    auto v=json_object_get(obj,key);
    return !v && optional ? "" : str(v);
}
unsigned integer(json_t *obj,const char *key,unsigned max) {
    auto v=json_object_get(obj,key);
    require(json_is_integer(v) && json_integer_value(v)>=0 &&
            uint64_t(json_integer_value(v))<=max,string("invalid ")+key);
    return unsigned(json_integer_value(v));
}
unsigned width(const string &f) {
    if (f=="u8") return 8;
    if (f=="u16le") return 16;
    if (f=="u32le") return 32;
    if (f=="u64le") return 64;
    return 0;
}
std::map<uint64_t,string> labels(json_t *obj,const char *key,uint64_t max) {
    std::map<uint64_t,string> out;
    auto v=json_object_get(obj,key);
    if (!v) return out;
    require(json_is_object(v),"expected map for "+string(key));
    const char *name; json_t *label;
    json_object_foreach(v,name,label) {
        uint64_t number;
        auto end=name+strlen(name);
        auto r=std::from_chars(name,end,number);
        require(r.ec==std::errc{} && r.ptr==end && number<=max,"invalid numeric key "+string(name));
        require(out.emplace(number,str(label)).second,"duplicate numeric key");
    }
    return out;
}
bool hex4(const string &s) {
    return s.size()==4 && s.find_first_not_of("0123456789ABCDEF")==string::npos;
}
bool family_selector(const string &s) {
    auto pos=s.find('#');
    return pos!=string::npos && pos>0 && s.substr(pos)=="####";
}
Rule parse_rule(json_t *v,Rule r) {
    keys(v,{"name","family","format","meaning","unit","source","enum","special","otherwise","bits","fields","reference"});
    r.family=json_object_get(v,"family");
    require(r.family!=bool(json_object_get(v,"name")),"specify exactly one selector");
    r.selector=prop(v,r.family?"family":"name");
    if (r.family) require(family_selector(r.selector)||r.selector=="linux-pstore","unsupported family");
    r.format=prop(v,"format"); r.meaning=prop(v,"meaning"); r.unit=prop(v,"unit",true);
    if (json_object_get(v,"source")) r.source=prop(v,"source");
    static const std::set<string> formats={"u8","u16le","u32le","u64le","u16le[]","guid[]",
        "ascii-z","languages","utf16-z","uuid-text","efi-load-option","device-path",
        "signature-list","sbat-lines","pstore","raw"};
    require(formats.count(r.format),"unknown format "+r.format);
    require((r.format=="pstore")== (r.family && r.selector=="linux-pstore"),"pstore requires linux-pstore family");
    unsigned w=width(r.format);
    for (auto k:{"enum","special","otherwise","bits","fields","unit"})
        require(!json_object_get(v,k)||w,"numeric metadata on non-scalar");
    require(!(json_object_get(v,"enum") && json_object_get(v,"special")),"conflicting labels");
    uint64_t max=w==64 ? UINT64_MAX : (uint64_t(1)<<w)-1;
    r.labels=labels(v,json_object_get(v,"enum")?"enum":"special",max);
    if (json_object_get(v,"otherwise")) {
        require(prop(v,"otherwise")=="reserved" && json_object_get(v,"enum"),"invalid enum fallback");
        r.reserved=true;
    }
    r.bits=labels(v,"bits",w?w-1:0);
    uint64_t used=0;
    for (auto &bit:r.bits) used|=uint64_t(1)<<bit.first;
    if (auto fields=json_object_get(v,"fields")) {
        require(json_is_array(fields),"expected fields array");
        size_t i; json_t *f;
        json_array_foreach(fields,i,f) {
            keys(f,{"lsb","width","name","unit"});
            unsigned lo=integer(f,"lsb",w-1), n=integer(f,"width",w-lo);
            require(n!=0,"zero-width field");
            uint64_t mask=(UINT64_MAX>>(64-n))<<lo;
            require(!(mask&used),"overlapping bit fields"); used|=mask;
            r.fields.push_back({lo,n,prop(f,"name"),prop(f,"unit",true)});
        }
    }
    if (auto ref=json_object_get(v,"reference")) {
        keys(ref,{"guid","family","label"});
        require((r.format=="u16le" || r.format=="u16le[]") && prop(ref,"guid")=="self" &&
                prop(ref,"label")=="description","unsupported reference");
        r.target=prop(ref,"family"); require(family_selector(r.target),"invalid reference family");
    }
    return r;
}
struct Document {
    string path;
    const char *embedded = nullptr;
};
const Document builtin[] = {
#include "builtin.inc"
};
void load_layer(evd_registry &reg,const std::vector<Document> &files,bool user) {
    std::set<Key> seen; std::set<string> known_aliases, known_layouts, known_sizes;
    for (const auto &file:files) {
        try {
            json_error_t err{};
            Json doc(file.embedded ? json_loads(file.embedded,JSON_REJECT_DUPLICATES,&err) :
                     json_load_file(file.path.c_str(),JSON_REJECT_DUPLICATES,&err),json_decref);
            if (!doc) throw runtime_error("line "+std::to_string(err.line)+": "+err.text);
            auto d=doc.get();
            keys(d,{"schema","guid","source","rules","guid_labels","layouts","signature_data_bytes"});
            require(integer(d,"schema",1)==1,"unsupported schema");
            Rule base; base.guid=canonical_guid(prop(d,"guid")); base.source=prop(d,"source");
            base.file=file.path; base.user=user;
            if (auto sizes=json_object_get(d,"signature_data_bytes")) {
                require(json_is_object(sizes),"signature_data_bytes must be an object");
                const char *k; json_t *v;
                json_object_foreach(sizes,k,v) {
                    auto id=canonical_guid(k);
                    require(known_sizes.insert(id).second,"duplicate signature size");
                    reg.signature_sizes[id]=integer(sizes,k,UINT32_MAX-16);
                }
            }
            if (auto layouts=json_object_get(d,"layouts")) {
                require(json_is_array(layouts),"layouts must be an array");
                size_t i; json_t *item;
                json_array_foreach(layouts,i,item) {
                    auto r=parse_rule(item,base);
                    require(!r.family && r.format=="u32le" && r.target.empty(),"invalid attribute layout");
                    require(r.selector=="variable_attributes" || r.selector=="load_option_attributes","unknown layout");
                    require(known_layouts.insert(r.selector).second,"duplicate layout");
                    auto id=r.selector;
                    reg.layouts.insert_or_assign(id,std::move(r));
                }
            }
            if (auto aliases=json_object_get(d,"guid_labels")) {
                require(json_is_object(aliases),"guid_labels must be an object");
                const char *k; json_t *v;
                json_object_foreach(aliases,k,v) {
                    auto id=canonical_guid(k);
                    require(known_aliases.insert(id).second,"duplicate GUID label");
                    reg.aliases[id]=str(v);
                }
            }
            auto rules=json_object_get(d,"rules"); require(json_is_array(rules),"missing rules array");
            size_t i; json_t *item;
            json_array_foreach(rules,i,item) {
                try {
                    auto r=parse_rule(item,base);
                    Key k{r.guid,r.selector}; require(seen.insert(k).second,"duplicate selector");
                    (r.family?reg.families:reg.exact).insert_or_assign(k,std::move(r));
                } catch (const std::exception &e) {
                    throw runtime_error("rule "+std::to_string(i+1)+": "+e.what());
                }
            }
        } catch (const std::exception &e) { throw runtime_error(file.path+": "+e.what()); }
    }
}
void directory(evd_registry &reg,const fs::path &dir,bool user) {
    if (!fs::exists(dir)) return;
    std::vector<fs::path> files;
    for (const auto &e:fs::directory_iterator(dir))
        if (e.path().extension()==".json" && e.is_regular_file()) files.push_back(e.path());
    std::sort(files.begin(),files.end());
    std::vector<Document> documents;
    for (const auto &path:files) documents.push_back({path.string()});
    load_layer(reg,documents,user);
}
}
string canonical_guid(string s) {
    if (s.size()!=36) throw runtime_error("invalid GUID length");
    for (size_t i=0;i<s.size();++i) {
        char &c=s[i];
        if (i==8||i==13||i==18||i==23) { require(c=='-',"invalid GUID separator"); continue; }
        if (c>='A' && c<='F') c+= 'a'-'A';
        require((c>='0'&&c<='9')||(c>='a'&&c<='f'),"invalid GUID digit");
    }
    return s;
}
const Rule *evd_registry::find(const string &g,const string &n) const {
    auto it=exact.find({g,n}); if (it!=exact.end()) return &it->second;
    string family;
    if (n.size()>4 && hex4(n.substr(n.size()-4))) family=n.substr(0,n.size()-4)+"####";
    else if (pstore_name(n,nullptr)) family="linux-pstore";
    auto f=families.find({g,family}); return f==families.end()?nullptr:&f->second;
}
void load_registry(evd_registry &reg,const char *system,const char *user) {
    load_layer(reg,{std::begin(builtin),std::end(builtin)},false);
    directory(reg,system?system:EVD_DATADIR,false);
    if (user) { if (*user) directory(reg,user,true); }
    else {
        fs::path base;
        if (auto x=std::getenv("XDG_CONFIG_HOME"); x && fs::path(x).is_absolute()) base=x;
        else if (auto home=std::getenv("HOME"); home && *home) base=fs::path(home)/".config";
        if (!base.empty()) directory(reg,base/"libefivardecode"/"registry.d",true);
    }
}
