extern unsigned long inertia_esp;
extern unsigned long inertia_ebx;
extern unsigned short g_0042;

    extern unsigned short inertia_ds;
void sub_1443d(void)
{

    unsigned int d;  // d
    unsigned short si;  // si
    si = g_0042;
    if (SEG_U16(inertia_ds, 6709 + si))
    {
        inertia_ebx = inertia_ebx & 0xffff0000 | (inertia_ebx & 0xffff) + 2 & 0xffff;
        inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
        return;
    }
}