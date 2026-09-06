extern unsigned long inertia_esp;

    extern unsigned short inertia_ds;
unsigned short sub_1431c(void)
{

    unsigned short tmp_17;
    unsigned short tmp_19;
    tmp_17 = SEG_U8(inertia_ds, 820);
    tmp_19 = SEG_U8(inertia_ds, 821);
    SEG_U16(inertia_ds, 820) = tmp_17 | tmp_19 << 8 | 1;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 + 2 & 0xffff;
    return SEG_U16(inertia_ss, inertia_esp & 0xffff);
}