unsigned short sub_153ea(void);

extern unsigned long inertia_esp;

    extern unsigned short inertia_ds;
void sub_14b4b(void)
{

    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    SEG_U16(inertia_ds, 138) = sub_153ea();
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}