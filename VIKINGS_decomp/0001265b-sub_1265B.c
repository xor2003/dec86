int sub_12515(unsigned short a0, unsigned short a1);

extern unsigned long inertia_edi;
extern unsigned long inertia_esi;
extern unsigned long inertia_esp;

    extern unsigned short xffff;
    extern unsigned short xffff0000;
    extern unsigned short inertia_ss;
void sub_1265b(void)
{
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    sub_12515(inertia_edi & 0xffff, inertia_esi & 0xffff);
    inertia_edi = inertia_edi & 0xffff0000 | SEG_U16(inertia_ss, inertia_esp & 0xffff) & 0xffff;
    inertia_esi = inertia_esi & 0xffff0000 | SEG_U16(inertia_ss, 2 + (inertia_esp & 0xffff)) & 0xffff;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 + 2 & 0xffff;
}