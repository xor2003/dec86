void sub_1689e(void);

extern unsigned long inertia_ecx;
extern unsigned long inertia_edi;

    extern unsigned short xffff0000;
    extern unsigned short xffff;
    extern unsigned short x800;
void sub_16dc1(void)
{
    unsigned short v16;  // 4137
    unsigned short v17;  // 4142
    unsigned short v18;  // 4151
    unsigned short v11;  // flags
    unsigned char v14;  // 4117

    inertia_ecx = inertia_ecx & 0xffff0000 | 43;
    do
    {
        inertia_ecx = inertia_ecx & 0xffff0000 | inertia_ecx & 0xffff & 0xffff;
        sub_1689e();
        v14 = (inertia_edi & 0xffff) + 2 ^ (inertia_edi & 0xffff) + 2 >> 4 ^ ((inertia_edi & 0xffff) + 2 ^ (inertia_edi & 0xffff) + 2 >> 4) >> 2 ^ ((inertia_edi & 0xffff) + 2 ^ (inertia_edi & 0xffff) + 2 >> 4 ^ ((inertia_edi & 0xffff) + 2 ^ (inertia_edi & 0xffff) + 2 >> 4) >> 2) >> 1;
        v16 = ((inertia_edi & 0xffff) + 2 >> 16 & 1 & 1) << 0 | (~(v14) & 1 & 1) << 2 | ((inertia_edi & 0xffff ^ 2 ^ (inertia_edi & 0xffff) + 2) >> 4 & 1 & 1) << 4 | (!((inertia_edi & 0xffff) + 2) & 1) << 6;
        v17 = (1 & (inertia_edi & 0xffff) + 2 >> 15 & 1) << 7;
        v18 = (~(inertia_edi & 0xffff ^ 2) & (inertia_edi & 0xffff ^ (inertia_edi & 0xffff) + 2)) >> 15 & 1 & 1;
        if ((v11 & 63274 | (v16 | v17 | v18 * 0x800) & 2261) >> 10 & 1 & 1)
            inertia_edi = inertia_edi & 0xffff0000 | (inertia_edi & 0xffff) + 2 & 0xffff;
        else
            inertia_edi = inertia_edi & 0xffff0000 | (inertia_edi & 0xffff) + 2 & 0xffff;
        inertia_ecx = inertia_ecx & 0xffff0000 | (inertia_ecx & 0xffff) - 1 & 0xffff;
    } while (!((inertia_ecx & 0xffff) != 1 ? 0 : 1));
    return;
}