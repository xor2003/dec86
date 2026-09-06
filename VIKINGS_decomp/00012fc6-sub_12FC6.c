void sub_12fe5(void);

extern unsigned short inertia_flags;
extern unsigned long inertia_edi;

    extern unsigned short inertia_ds;
    extern unsigned short xffff;
    extern unsigned short xffff0000;
    extern unsigned short x800;
void sub_12fc6(void)
{
    unsigned short v11;  // flags
    unsigned short v12;  // 4117
    unsigned short v13;  // 4117
    unsigned short v4;  // flags
    unsigned short v7;  // 4117
    unsigned short v8;  // 4132
    unsigned short v9;  // 4137
    unsigned short v10;  // 4145
    unsigned char v6;  // 4112

    v4 = inertia_flags;
    v11 = inertia_flags;
    inertia_edi = inertia_edi & 0xffff0000 | SEG_U16(inertia_ds, 882) - 2 & 0xffff;
    do
    {
        sub_12fe5();
        v6 = (inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4 ^ ((inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4) >> 2 ^ ((inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4 ^ ((inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4) >> 2) >> 1;
        v7 = (~((inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4 ^ ((inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4) >> 2 ^ ((inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4 ^ ((inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4) >> 2) >> 1) & 1 & 1) << 2;
        v8 = 0 | ((inertia_edi & 0xffff) < 2 & 1) << 0 | (~(v6) & 1 & 1) << 2 | ((inertia_edi & 0xffff ^ 2 ^ (inertia_edi & 0xffff) - 2) >> 4 & 1 & 1) << 4 | (!((inertia_edi & 0xffff) - 2) & 1) << 6;
        v9 = (1 & (inertia_edi & 0xffff) - 2 >> 15 & 1) << 7;
        v10 = ((inertia_edi & 0xffff ^ 2) & (inertia_edi & 0xffff ^ (inertia_edi & 0xffff) - 2)) >> 15 & 1 & 1;
        v11 = v4 & 63274 | (0 | ((inertia_edi & 0xffff) < 2 & 1) << 0 | v7 | ((inertia_edi & 0xffff ^ 2 ^ (inertia_edi & 0xffff) - 2) >> 4 & 1 & 1) << 4 | (!((inertia_edi & 0xffff) - 2) & 1) << 6 | (1 & (inertia_edi & 0xffff) - 2 >> 15 & 1) << 7 | (((inertia_edi & 0xffff ^ 2) & (inertia_edi & 0xffff ^ (inertia_edi & 0xffff) - 2)) >> 15 & 1 & 1) << 11) & 2261;
        if ((v4 & 63274 | (v8 | v9 | v10 * 0x800) & 2261) >> 10 & 1 & 1)
        {
            v12 = (~((inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4 ^ ((inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4) >> 2 ^ ((inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4 ^ ((inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4) >> 2) >> 1) & 1 & 1) << 2;
            v4 = v11 & 63274 | (0 | ((inertia_edi & 0xffff) < 2 & 1) << 0 | v12 | ((inertia_edi & 0xffff ^ 2 ^ (inertia_edi & 0xffff) - 2) >> 4 & 1 & 1) << 4 | (!((inertia_edi & 0xffff) - 2) & 1) << 6 | (1 & (inertia_edi & 0xffff) - 2 >> 15 & 1) << 7 | (((inertia_edi & 0xffff ^ 2) & (inertia_edi & 0xffff ^ (inertia_edi & 0xffff) - 2)) >> 15 & 1 & 1) << 11) & 2261;
            inertia_edi = inertia_edi & 0xffff0000 | (inertia_edi & 0xffff) - 2 & 0xffff;
        }
        else
        {
            v13 = (~((inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4 ^ ((inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4) >> 2 ^ ((inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4 ^ ((inertia_edi & 0xffff) - 2 ^ (inertia_edi & 0xffff) - 2 >> 4) >> 2) >> 1) & 1 & 1) << 2;
            v4 = v11 & 63274 | (0 | ((inertia_edi & 0xffff) < 2 & 1) << 0 | v13 | ((inertia_edi & 0xffff ^ 2 ^ (inertia_edi & 0xffff) - 2) >> 4 & 1 & 1) << 4 | (!((inertia_edi & 0xffff) - 2) & 1) << 6 | (1 & (inertia_edi & 0xffff) - 2 >> 15 & 1) << 7 | (((inertia_edi & 0xffff ^ 2) & (inertia_edi & 0xffff ^ (inertia_edi & 0xffff) - 2)) >> 15 & 1 & 1) << 11) & 2261;
            inertia_edi = inertia_edi & 0xffff0000 | (inertia_edi & 0xffff) - 2 & 0xffff;
        }
    } while (!(!(v4 & 128) ? 0 : 1));
    return;
}