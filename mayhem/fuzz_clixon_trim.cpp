#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" char *clixon_trim(char *str);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);

    char* str = strdup(provider.ConsumeRandomLengthString().c_str());
    clixon_trim(str);
    free(str);

    return 0;
}