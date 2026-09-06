unsigned short sub_163ac(unsigned short a0);

extern unsigned long inertia_esp;
extern unsigned long inertia_esi;

    extern unsigned short xffff;
    extern unsigned short xffff0000;
    extern unsigned short inertia_ds;
void sub_14501(void)
{

    unsigned int eax;  // eax
    unsigned short tmp_38;
    unsigned short tmp_40;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    eax = sub_163ac(2);
    inertia_esi = inertia_esi & 0xffff0000 | 2;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    tmp_38 = SEG_U8(inertia_ds, (inertia_esi & 0xffff) - 30802);
    tmp_40 = SEG_U8(inertia_ds, (inertia_esi & 0xffff) - 30801);
    /* unsupported computed goto: ... */ return;
}