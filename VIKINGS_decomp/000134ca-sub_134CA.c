extern unsigned short g_007A;
extern unsigned long inertia_ebx;
extern unsigned long inertia_esp;

    extern unsigned short inertia_ds;
    extern unsigned short inertia_es;
    extern unsigned short xffff;
    extern unsigned short xffff0000;
void sub_134ca(void)
{

    SEG_U16(inertia_ds, 122) = SEG_U16(inertia_es, inertia_ebx & 0xffff);
    g_007A += 2;
    inertia_ebx = inertia_ebx & 0xffff0000 | SEG_U16(inertia_es, inertia_ebx & 0xffff) & 0xffff;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}