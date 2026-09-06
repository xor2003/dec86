unsigned short sub_15445(void);

extern unsigned long inertia_esp;

    extern unsigned short inertia_ds;
void sub_14b60(void)
{

    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    SEG_U16(inertia_ds, 138) = sub_15445();
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}