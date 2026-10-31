// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "efivardecode.h"
#include <jansson.h>
#include <charconv>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
namespace fs = std::filesystem;
using std::string;
struct Bad { size_t offset; string reason; };
struct Span {
    const uint8_t *p;
    size_t n, off;
    Span sub(size_t pos, size_t len) const {
        if (pos > n || len > n-pos) throw Bad{off + (pos > n ? n : pos), "truncated field"};
        return {p ? p + pos : nullptr, len, off + pos};
    }
    uint64_t le(size_t pos, size_t width) const {
        auto s = sub(pos,width);
        uint64_t v = 0;
        for (size_t i=0;i<width;++i) v |= uint64_t(s.p[i]) << (8*i);
        return v;
    }
};
// Limits the tree expansion of untrusted compound values. Reentrant calls
// save and restore their caller's budget.
inline thread_local size_t node_budget = 0;
struct NodeBudget {
    size_t saved = node_budget;
    NodeBudget() { node_budget = 262144; }
    ~NodeBudget() { node_budget = saved; }
};
struct evd_node {
    evd_kind kind;
    string field;
    size_t offset, length;
    uint64_t number = 0;
    string text, unit;
    std::vector<evd_node> children;
    evd_node(evd_kind k, string f, Span s):kind(k),field(std::move(f)),offset(s.off),length(s.n) {}
    evd_node &add(evd_kind k, string f, Span s) {
        if (!node_budget) throw std::length_error("decoded node limit exceeded");
        --node_budget;
        return children.emplace_back(k,std::move(f),s);
    }
};
struct Rule {
    string guid, selector, format, meaning, source, file, unit, target;
    bool user=false, family=false, reserved=false;
    std::map<uint64_t,string> labels, bits;
    struct Field { unsigned lsb,width; string name,unit; };
    std::vector<Field> fields;
};
using Key = std::pair<string,string>;
struct evd_registry {
    std::map<Key,Rule> exact, families;
    std::map<string,Rule> layouts;
    std::map<string,string> aliases;
    std::map<string,size_t> signature_sizes;
    const Rule *find(const string &,const string &) const;
};
struct evd_result {
    evd_status status=EVD_OK;
    size_t error_offset=0;
    evd_node attrs{EVD_UINT,"attributes",{nullptr,0,0}};
    string name,guid;
    string diagnostic,file,selector,source,meaning;
    bool user=false;
    std::vector<uint8_t> payload;
    evd_node root{EVD_BYTES,"value",{nullptr,0,0}};
};
string canonical_guid(string);
string wire_guid(Span);
string utf16(Span);
void load_registry(evd_registry &,const char *,const char *);
void device_path(evd_node &,Span);
void load_option(evd_node &,Span);
void signatures(evd_node &,Span,const evd_registry &);
bool pstore_name(const string &,evd_node *);
