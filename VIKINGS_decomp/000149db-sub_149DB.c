void sub_154a3(void);

extern unsigned short inertia_flags;
extern unsigned long inertia_eax;
extern unsigned short g_008A;

    extern unsigned short x800;
void sub_149DB(void)
{
    unsigned short v6;  // 4129
    unsigned short v8;  // 4141
    unsigned short v9;  // 4148
    unsigned short v10;  // flags
    unsigned short v11;  // flags
    unsigned char v7;  // 4133

    v10 = inertia_flags;
    sub_154a3();
    v6 = 0 | (g_008A < inertia_eax & 1) << 0;
    v7 = (g_008A - inertia_eax ^ g_008A - inertia_eax >> 4) >> 2;
    v8 = (~(g_008A - inertia_eax ^ g_008A - inertia_eax >> 4 ^ (g_008A - inertia_eax ^ g_008A - inertia_eax >> 4) >> 2 ^ (g_008A - inertia_eax ^ g_008A - inertia_eax >> 4 ^ v7) >> 1) & 1 & 1) << 2;
    v9 = (g_008A ^ inertia_eax ^ g_008A - inertia_eax) >> 4 & 1 & 1;
    v11 = v10 & 63274 | (v6 | v8 | v9 << 4 | (!(g_008A - inertia_eax) & 1) << 6 | (1 & g_008A - inertia_eax >> 15 & 1) << 7 | (((g_008A ^ inertia_eax) & (g_008A ^ g_008A - inertia_eax)) >> 15 & 1 & 1) << 11) & 2261;
    if (!(v11 & 0x800))
    {
        if (!(!(v11 & 128) ? 0 : 1))
            goto LABEL_149ef;
    }
    else
    {
        if (!(v11 & 128 ? 0 : 1))
        {
LABEL_149ef:
            return;
        }
    }
}