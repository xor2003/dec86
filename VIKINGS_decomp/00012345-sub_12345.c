extern unsigned long inertia_esp;

    extern unsigned short inertia_ds;
void sub_12345(void)
{
    SEG_U16(inertia_ds, 950) = 0;
    SEG_U16(inertia_ds, 952) = 0;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}