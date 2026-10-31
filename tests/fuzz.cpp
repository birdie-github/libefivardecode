// SPDX-License-Identifier: LGPL-2.1-or-later
#include "efivardecode.h"
#include <cstdlib>
#include <memory>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data,size_t len) {
    static std::unique_ptr<evd_registry,decltype(&evd_registry_free)> reg(
        evd_registry_open(EVD_TEST_REGISTRY,""),evd_registry_free);
    if (!reg) std::abort();
    if (!len) return 0;
    const char *names[]={"Boot0000","ConIn","PK"};
    evd_input in{names[data[0]%3],"8be4df61-93ca-11d2-aa0d-00e098032b8c",7,data+1,len-1};
    evd_result_free(evd_decode(reg.get(),&in,nullptr,nullptr));
    return 0;
}
