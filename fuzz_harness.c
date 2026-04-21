#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// enc_1 and enc_2 taken from the decompiled output
// provided by hexrays for the crack_me (dogbolt decompiler)
unsigned char enc_1[32] = {
    49, 198, 220, 247, 184, 186, 157, 142, 110, 65, 80, 23, 51, 7, 229, 240, 
    194, 212, 146, 134, 134, 124, 99, 115, 82, 51, 22, 12, 238, 236, 204, 0
};

unsigned char enc_2[14] = { 
    25, 227, 215, 190, 132, 145, 57, 86, 4, 60, 4, 27, 246, 139 
};

// hiden function inspirted (with a bit of manipulation) taken from
// Ghidra decompiler output produced by the dogbolt decompiler
void hidden_function(char *param_1, long param_2) {
    long lVar1;
    unsigned char bVar2;

    // represents combination of
    // byte local_28[31] followed by undefined local_9
    // (undefined_local9 is used to null terminate the array before printing)
    char local_28[32];

    if (param_2 == 0xe) {
        bVar2 = 0x7f;
        lVar1 = 0;
        while ((unsigned char)param_1[lVar1] == (unsigned char)(bVar2 ^ enc_2[lVar1])) {
            lVar1 = lVar1 + 1;
            bVar2 = bVar2 + 0x17;
            if (lVar1 == 0xe) {
                bVar2 = 0x77;
                lVar1 = 0;
                do {
                    local_28[lVar1] = (char)(bVar2 ^ enc_1[lVar1]);
                    lVar1 = lVar1 + 1;
                    bVar2 = bVar2 + 0x13;
                } while (lVar1 != 0x1f);
                local_28[0x1f] = '\0';
                puts(local_28);

		// earlier there was a return here, so added an
                // abort so that fuzzer registers this as a crash which we can detect
                abort(); 
            }
        }
    }
}

int main() {
    char buf[14];

   // per process invocation, this loop runs 1000 times
   // (stdin reset per iteration) 
    while (__AFL_LOOP(1000)) {
        memset(buf, 0, sizeof(buf));
        ssize_t n = read(0, buf, 14);
        if (n == 14) {
            hidden_function(buf, 14);
        }
    }
    return 0;
}

