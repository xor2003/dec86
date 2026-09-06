void sub_158d7(void);

extern unsigned short inertia_flags;
extern unsigned long inertia_ebx;

    extern unsigned short inertia_es;
    extern unsigned short xffff;
void sub_1446d(void)
{
    unsigned short v10;  // 4167
    unsigned short v11;  // 4172
    unsigned short v12;  // flags
    unsigned short local_2;  // [bp-0x2]
    unsigned char v6;  // esi
    unsigned char v8;  // 4152

    v12 = inertia_flags;
    local_2 = 2;
    v6 = SEG_U16(inertia_es, inertia_ebx & 0xffff);
    inertia_ebx = inertia_ebx & 0xffff0000 | (inertia_ebx & 0xffff) + 1 & 0xffff;
    v8 = v6 & 0xff ^ (v6 & 0xff) >> 4 ^ (v6 & 0xff ^ (v6 & 0xff) >> 4) >> 2 ^ (v6 & 0xff ^ (v6 & 0xff) >> 4 ^ (v6 & 0xff ^ (v6 & 0xff) >> 4) >> 2) >> 1;
    v10 = 0 | (0 & 1) << 0 | (~(v8) & 1 & 1) << 2 | 0 << 4 | (!(v6 & 0xff) & 1) << 6;
    v11 = (1 & (v6 & 0xff) >> 15 & 1) << 7;
    sub_158d7();
    if (!0)
        return;
    return;
}