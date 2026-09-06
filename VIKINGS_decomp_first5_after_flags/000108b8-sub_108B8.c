void sub_12ce4(void);

extern unsigned long inertia_esp;

    extern unsigned short inertia_ds;
void sub_108B8(void)
{
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    sub_12ce4();
    SEG_U16(inertia_ds, 9673) = 39;
    SEG_U16(inertia_ds, 962) = 0;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}