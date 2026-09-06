void sub_1689e(void);

extern unsigned long inertia_edi;

    extern unsigned short xffff;
    extern unsigned short x800;
    extern unsigned short xffff0000;
void sub_16dd9(void)
{
    unsigned short v2;  // cx
    unsigned short v10;  // 4160
    unsigned short v11;  // 4165
    unsigned short v12;  // 4174
    unsigned short v4;  // flags
    unsigned short v5;  // cx
    unsigned char v8;  // 4140

    v2 = 25;
    do
    {
        v5 = v2;
        sub_1689e();
        v8 = (inertia_edi & 0xffff) + 688 ^ (inertia_edi & 0xffff) + 688 >> 4 ^ ((inertia_edi & 0xffff) + 688 ^ (inertia_edi & 0xffff) + 688 >> 4) >> 2 ^ ((inertia_edi & 0xffff) + 688 ^ (inertia_edi & 0xffff) + 688 >> 4 ^ ((inertia_edi & 0xffff) + 688 ^ (inertia_edi & 0xffff) + 688 >> 4) >> 2) >> 1;
        v10 = ((inertia_edi & 0xffff) + 688 >> 16 & 1 & 1) << 0 | (~(v8) & 1 & 1) << 2 | ((inertia_edi & 0xffff ^ 688 ^ (inertia_edi & 0xffff) + 688) >> 4 & 1 & 1) << 4 | (!((inertia_edi & 0xffff) + 688) & 1) << 6;
        v11 = (1 & (inertia_edi & 0xffff) + 688 >> 15 & 1) << 7;
        v12 = (~(inertia_edi & 0xffff ^ 688) & (inertia_edi & 0xffff ^ (inertia_edi & 0xffff) + 688)) >> 15 & 1 & 1;
        if ((v4 & 63274 | (v10 | v11 | v12 * 0x800) & 2261) >> 10 & 1 & 1)
            inertia_edi = inertia_edi & 0xffff0000 | (inertia_edi & 0xffff) + 688 & 0xffff;
        else
            inertia_edi = inertia_edi & 0xffff0000 | (inertia_edi & 0xffff) + 688 & 0xffff;
        v2 = v5 - 1;
    } while (!(v5 != 1 ? 0 : 1));
    return;
}