extern unsigned short g_0334;
extern unsigned short g_03C2;
void sub_12e2d(void);

    extern unsigned short inertia_ds;
void sub_12e16(void)
{
    unsigned short v3;  // si
    unsigned short v8;  // 4147
    unsigned short v9;  // 4152
    unsigned short v10;  // flags
    unsigned char v5;  // 4113
    unsigned char v6;  // 4115
    unsigned char v7;  // 4132

    v3 = g_03C2;
    sub_12e2d();
    SEG_U16(inertia_ds, 962) = v3;
    if (g_03C2 == 0xffff)
    {
        v5 = SEG_U8(inertia_ds, 820);
        v6 = SEG_U8(inertia_ds, 821);
        v7 = (v5 | v6 << 8 | 2) ^ (v5 | v6 << 8 | 2) >> 4 ^ ((v5 | v6 << 8 | 2) ^ (v5 | v6 << 8 | 2) >> 4) >> 2 ^ ((v5 | v6 << 8 | 2) ^ (v5 | v6 << 8 | 2) >> 4 ^ ((v5 | v6 << 8 | 2) ^ (v5 | v6 << 8 | 2) >> 4) >> 2) >> 1;
        v8 = (~(v7) & 1 & 1) << 2 | (!(v5 | v6 << 8 | 2) & 1) << 6;
        v9 = (1 & (v5 | v6 << 8 | 2) >> 15 & 1) << 7;
        if (!((v10 & 63274 | (v8 | v9) & 2261) >> 10 & 1))
        {
            SEG_U16(inertia_ds, 820) = g_0334 | 2;
            return;
        }
        SEG_U16(inertia_ds, 820) = g_0334 | 2;
        return;
    }
    else
    {
        return;
    }
}