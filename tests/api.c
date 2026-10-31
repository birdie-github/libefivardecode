// SPDX-License-Identifier: LGPL-2.1-or-later
#include "efivardecode.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); return 1; } } while (0)
int main(int argc,char **argv) {
    CHECK(argc==2);
    evd_registry *reg=evd_registry_open(argv[1],"");
    CHECK(reg);
    unsigned char data[]={1,0};
    evd_input in={"Timeout","8BE4DF61-93CA-11D2-AA0D-00E098032B8C",7,data,sizeof(data)};
    evd_result *r=evd_decode(reg,&in,NULL,NULL);
    CHECK(r && evd_result_status(r)==EVD_OK);
    data[0]=9;
    evd_registry_free(reg);
    CHECK(evd_uint(evd_root(r))==1 && strcmp(evd_unit(evd_root(r)),"second")==0);
    size_t n;
    CHECK(evd_payload(r,&n)[0]==1 && n==2 && evd_uint(evd_attributes(r))==7);
    evd_result_free(r);
    return 0;
}
