void sub_13bbd(void);

extern unsigned short inertia_flags;

    extern unsigned short inertia_ds;
void sub_13ba5(void)
{

    unsigned short iter;  // di
    unsigned short v12;  // flags
    unsigned short v13;  // 4108
    unsigned short v14;  // 4120
    unsigned short v4;  // flags
    unsigned short v6;  // 4110
    unsigned short v8;  // 4122
    v4 = inertia_flags;
    v12 = inertia_flags;
    SEG_U16(inertia_ds, 66) = 0xffff;
    iter = 0;
    while (1)
    {
        sub_13bbd();
        if (!(v4 & 1 ? 0 : 1))
            break;
        v6 = 0 | (iter + 14 >> 16 & 1 & 1) << 0;
        v8 = (~(iter + 14 ^ iter + 14 >> 4 ^ (iter + 14 ^ iter + 14 >> 4) >> 2 ^ (iter + 14 ^ iter + 14 >> 4 ^ (iter + 14 ^ iter + 14 >> 4) >> 2) >> 1) & 1 & 1) << 2;
        v12 = v4 & 63274 | (v6 | v8 | ((iter ^ 14 ^ iter + 14) >> 4 & 1 & 1) << 4 | (!(iter + 14) & 1) << 6 | (1 & iter + 14 >> 15 & 1) << 7 | ((~(iter ^ 14) & (iter ^ iter + 14)) >> 15 & 1 & 1) << 11) & 2261;
        v13 = 0 | (iter + 14 >> 16 & 1 & 1) << 0;
        v14 = (~(iter + 14 ^ iter + 14 >> 4 ^ (iter + 14 ^ iter + 14 >> 4) >> 2 ^ (iter + 14 ^ iter + 14 >> 4 ^ (iter + 14 ^ iter + 14 >> 4) >> 2) >> 1) & 1 & 1) << 2;
        v4 = v12 & 63274 | (v13 | v14 | ((iter ^ 14 ^ iter + 14) >> 4 & 1 & 1) << 4 | (!(iter + 14) & 1) << 6 | (1 & iter + 14 >> 15 & 1) << 7 | ((~(iter ^ 14) & (iter ^ iter + 14)) >> 15 & 1 & 1) << 11) & 2261;
        iter += 14;
    }
    return;
}