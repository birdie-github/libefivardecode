// SPDX-License-Identifier: LGPL-2.1-or-later
#include "efivardecode.h"
#include <jansson.h>
#include <algorithm>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>
#include <vector>
namespace fs=std::filesystem;
using std::string;
using std::runtime_error;
namespace {
const char *usage=
    "Usage: efivardecode --efivarfs-dir DIR [--name NAME] [--guid GUID]\n"
    "       efivardecode --payload FILE --name NAME --guid GUID --attrs MASK\n"
    "Options: --json  --verbose  --registry-dir DIR  --user-registry-dir DIR\n"
    "         --no-user-registry  --help\n";
string quote(const string &s) {
    auto *v=json_stringn(s.data(),s.size());
    if (!v) throw runtime_error("invalid UTF-8 or out of memory");
    auto *raw=json_dumps(v,JSON_ENCODE_ANY); json_decref(v);
    if (!raw) throw std::bad_alloc();
    std::unique_ptr<char,decltype(&std::free)> p(raw,std::free);
    return raw;
}
string visible(const string &s) {
    if (s.find_first_of("\x1b\r\n\t")!=string::npos ||
        std::any_of(s.begin(),s.end(),[](unsigned char c){return c<32 || c==127;}))
        return quote(s);
    return s;
}
string hex(const uint8_t *p,size_t n,bool spaces) {
    constexpr char digits[]="0123456789ABCDEF";
    string out;
    for (size_t i=0;i<n;++i) {
        if (spaces && i) out+=' ';
        out+=digits[p[i]>>4]; out+=digits[p[i]&15];
    }
    return out;
}
string guid(string s) {
    if (s.size()!=36) throw runtime_error("expected a canonical GUID");
    for (size_t i=0;i<s.size();++i) {
        if (i==8||i==13||i==18||i==23) {
            if (s[i]!='-') throw runtime_error("invalid GUID separator");
        } else {
            if (s[i]>='A'&&s[i]<='F') s[i]+='a'-'A';
            if (string("0123456789abcdef").find(s[i])==string::npos) throw runtime_error("invalid GUID digit");
        }
    }
    return s;
}
struct Value { uint32_t attrs; std::vector<uint8_t> data; };
using Key=std::pair<string,string>;
using Snapshot=std::map<Key,Value>;
Value read(const fs::path &path,bool header,uint32_t attrs=0) {
    std::ifstream file(path,std::ios::binary);
    if (!file) throw runtime_error("cannot open "+path.string());
    Value value{attrs,{}};
    if (header) {
        unsigned char a[4];
        if (!file.read(reinterpret_cast<char *>(a),4)) throw runtime_error("short attribute header: "+path.string());
        value.attrs=uint32_t(a[0])|(uint32_t(a[1])<<8)|(uint32_t(a[2])<<16)|(uint32_t(a[3])<<24);
    }
    char block[8192];
    while (file) {
        file.read(block,sizeof(block));
        value.data.insert(value.data.end(),block,block+file.gcount());
    }
    if (!file.eof() || file.bad()) throw runtime_error("read failed: "+path.string());
    return value;
}
int lookup(void *ctx,const char *g,const char *name,const uint8_t **p,size_t *n) {
    auto &snapshot=*static_cast<const Snapshot *>(ctx);
    auto it=snapshot.find({name,g});
    if (it==snapshot.end()) return 0;
    *p=it->second.data.data(); *n=it->second.data.size(); return 1;
}
void json_node(const evd_node *n,const uint8_t *base) {
    const char *kinds[]={"record","list","uint","text","guid","bytes","reference"};
    auto kind=evd_node_kind(n); size_t off=evd_offset(n),len=evd_length(n);
    std::cout<<"{\"field\":"<<quote(evd_field(n))<<",\"kind\":"<<quote(kinds[kind])
             <<",\"offset\":"<<off<<",\"length\":"<<len;
    if (kind==EVD_UINT || kind==EVD_REFERENCE) std::cout<<",\"number\":"<<evd_uint(n);
    if (*evd_text(n)||kind==EVD_TEXT) std::cout<<",\"text\":"<<quote(evd_text(n));
    if (*evd_unit(n)) std::cout<<",\"unit\":"<<quote(evd_unit(n));
    if (kind==EVD_BYTES) std::cout<<",\"hex\":"<<quote(hex(base?base+off:nullptr,len,false));
    if (evd_count(n)) {
        std::cout<<",\"children\":[";
        for (size_t i=0;i<evd_count(n);++i) {
            if (i) std::cout<<',';
            json_node(evd_child(n,i),base);
        }
        std::cout<<']';
    }
    std::cout<<'}';
}
string summary(const evd_node *n,const uint8_t *p) {
    if (*evd_text(n)) return visible(evd_text(n));
    if (evd_node_kind(n)==EVD_UINT) {
        string v=std::to_string(evd_uint(n));
        if (*evd_unit(n)) v+=" "+string(evd_unit(n))+(evd_uint(n)==1?"":"s");
        for (size_t i=0;i<evd_count(n);++i) {
            auto field=evd_child(n,i); v+=" ["+string(evd_field(field))+"="+summary(field,p)+"]";
        }
        return v;
    }
    if (evd_node_kind(n)==EVD_BYTES) {
        auto len=evd_length(n);
        return hex(p?p+evd_offset(n):nullptr,std::min<size_t>(len,24),true)+
               (len>24?" … ("+std::to_string(len)+" bytes)":"");
    }
    if (evd_node_kind(n)==EVD_LIST && evd_count(n)) {
        auto first=evd_child(n,0);
        if (string(evd_field(first))=="signature_list") {
            size_t count=0;
            for (size_t i=0;i<evd_count(n);++i) {
                auto group=evd_child(n,i);
                for (size_t j=0;j<evd_count(group);++j) {
                    auto field=evd_child(group,j);
                    if (string(evd_field(field))=="entries") count+=evd_count(field);
                }
            }
            return std::to_string(count)+" signatures in "+std::to_string(evd_count(n))+" lists";
        }
        auto kind=evd_node_kind(first);
        if (kind==EVD_REFERENCE || kind==EVD_TEXT || kind==EVD_GUID) {
            string v;
            for (size_t i=0;i<evd_count(n);++i) {
                if (i) v+=", ";
                v+=visible(evd_text(evd_child(n,i)));
            }
            return v;
        }
    }
    for (size_t i=0;i<evd_count(n);++i) {
        auto field=evd_child(n,i);
        if (string(evd_field(field))=="description") return visible(evd_text(field));
    }
    return std::to_string(evd_count(n))+" items";
}
void details(const evd_node *n,const uint8_t *p,unsigned depth) {
    for (size_t i=0;i<evd_count(n);++i) {
        auto c=evd_child(n,i);
        std::cout<<string(depth*2,' ')<<evd_field(c)<<": "<<summary(c,p)<<'\n';
        details(c,p,depth+1);
    }
}
void show(const Key &key,const Value &v,const evd_result *r,bool json,bool verbose) {
    const char *states[]={"ok","unknown","malformed"};
    auto status=evd_result_status(r); auto root=evd_root(r);
    size_t len; auto data=evd_payload(r,&len);
    if (json) {
        std::cout<<"{\"name\":"<<quote(key.first)<<",\"guid\":"<<quote(key.second)
            <<",\"attributes\":"<<v.attrs<<",\"status\":"<<quote(states[status])
            <<",\"meaning\":"<<quote(evd_meaning(r))<<",\"rule_file\":"<<quote(evd_rule_file(r))
            <<",\"selector\":"<<quote(evd_rule_selector(r))<<",\"source\":"<<quote(evd_source(r))
            <<",\"user_rule\":"<<(evd_user_rule(r)?"true":"false")<<",\"value\":";
        json_node(root,data);
        std::cout<<",\"attribute_fields\":";
        json_node(evd_attributes(r),nullptr);
        if (status==EVD_MALFORMED) std::cout<<",\"error_offset\":"<<evd_error_offset(r)
            <<",\"diagnostic\":"<<quote(evd_diagnostic(r))<<",\"raw_hex\":"<<quote(hex(data,len,false));
        std::cout<<'}';
    } else {
        std::cout<<visible(key.first)<<"  ";
        if (status==EVD_MALFORMED) std::cout<<"malformed at byte "<<evd_error_offset(r)<<": "<<evd_diagnostic(r);
        else std::cout<<summary(root,data)<<(status==EVD_UNKNOWN?"  [unknown]":"");
        std::cout<<'\n';
        if (verbose) {
            std::cout<<"  GUID "<<key.second<<"  attributes "<<v.attrs<<"  "<<evd_meaning(r)<<'\n';
            details(root,data,1);
        }
    }
}
int run(int argc,char **argv) {
    std::map<string,string> opts; bool json=false,verbose=false;
    for (int i=1;i<argc;++i) {
        string arg=argv[i];
        if (arg=="--help") { std::cout<<usage; return 0; }
        if (arg=="--json") { json=true; continue; }
        if (arg=="--verbose") { verbose=true; continue; }
        if (arg=="--no-user-registry") { opts["--user-registry-dir"]=""; continue; }
        const string valid[]={"--name","--guid","--attrs","--payload","--efivarfs-dir","--registry-dir","--user-registry-dir"};
        if (std::find(std::begin(valid),std::end(valid),arg)==std::end(valid)||++i==argc)
            throw runtime_error("invalid argument "+arg+"\n"+usage);
        opts[arg]=argv[i];
    }
    auto arg=[&](const char *k)->const char *{ auto i=opts.find(k); return i==opts.end()?nullptr:i->second.c_str(); };
    bool dir=arg("--efivarfs-dir")!=nullptr;
    if (dir==bool(arg("--payload")) || (dir && arg("--attrs"))) throw runtime_error(usage);
    using Registry=std::unique_ptr<evd_registry,decltype(&evd_registry_free)>;
    Registry reg(evd_registry_open(arg("--registry-dir"),arg("--user-registry-dir")),evd_registry_free);
    if (!reg) throw runtime_error(evd_error());
    Snapshot snapshot;
    string filter=arg("--guid")?guid(arg("--guid")):"";
    if (dir) {
        for (const auto &e:fs::directory_iterator(arg("--efivarfs-dir"))) {
            if (!fs::is_regular_file(e.symlink_status())) continue;
            string file=e.path().filename().string();
            if (file.size()<38 || file[file.size()-37]!='-') continue;
            Key k{file.substr(0,file.size()-37),guid(file.substr(file.size()-36))};
            if (!snapshot.emplace(k,read(e.path(),true)).second) throw runtime_error("duplicate variable "+file);
        }
    } else {
        if (!arg("--attrs")||!arg("--name")||filter.empty()) throw runtime_error(usage);
        string mask=arg("--attrs"); const char *start=mask.data(),*end=start+mask.size();
        int base=10; if (mask.compare(0,2,"0x")==0) { start+=2; base=16; }
        uint32_t attrs; auto result=std::from_chars(start,end,attrs,base);
        if (result.ec!=std::errc{} || result.ptr!=end) throw runtime_error("invalid attributes");
        snapshot.emplace(Key{arg("--name"),filter},read(arg("--payload"),false,attrs));
    }
    std::vector<Snapshot::const_iterator> selected;
    for (auto it=snapshot.begin();it!=snapshot.end();++it) {
        if (arg("--name") && it->first.first!=arg("--name")) continue;
        if (!filter.empty() && filter!=it->first.second) continue;
        selected.push_back(it);
    }
    if (arg("--name") && selected.size()>1) throw runtime_error("ambiguous name: specify --guid");
    if (selected.empty() && (arg("--name") || !filter.empty())) throw runtime_error("no matching variable");
    if (json) std::cout<<"[";
    bool first=true,malformed=false;
    for (auto it:selected) {
        auto &[key,v]=*it;
        evd_input in{key.first.c_str(),key.second.c_str(),v.attrs,v.data.data(),v.data.size()};
        std::unique_ptr<evd_result,decltype(&evd_result_free)> r(
            evd_decode(reg.get(),&in,dir?lookup:nullptr,&snapshot),evd_result_free);
        if (!r) throw runtime_error(evd_error());
        if (json && !first) std::cout<<',';
        first=false; show(key,v,r.get(),json,verbose);
        malformed|=evd_result_status(r.get())==EVD_MALFORMED;
    }
    if (json) std::cout<<"]\n";
    return malformed?2:0;
}
}
int main(int argc,char **argv) {
    try { return run(argc,argv); }
    catch (const std::exception &e) { std::cerr<<"efivardecode: "<<e.what()<<'\n'; return 1; }
}
