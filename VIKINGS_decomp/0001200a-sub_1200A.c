extern unsigned long inertia_esp;

    extern unsigned short inertia_ds;
void sub_1200a(void)
{
    SEG_U16(inertia_ds, 1077) = 0xffff;
    SEG_U16(inertia_ds, 1079) = 0xffff;
    SEG_U16(inertia_ds, 1081) = 0xffff;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}