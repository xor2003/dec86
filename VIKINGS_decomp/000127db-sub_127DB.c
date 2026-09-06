extern unsigned long inertia_ebx;
extern unsigned long inertia_esp;
extern unsigned short g_0334;

    extern unsigned short inertia_ds;
void sub_127db(void)
{

    SEG_U16(inertia_ds, 820) = g_0334 | 4;
    inertia_ebx = inertia_ebx & 0xffff0000 | (inertia_ebx & 0xffff) + 2 & 0xffff;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}