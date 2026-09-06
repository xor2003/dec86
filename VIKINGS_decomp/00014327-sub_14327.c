void sub_13c93(void);

extern unsigned long inertia_esp;

unsigned short sub_14327(void)
{
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    sub_13c93();
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 + 2 & 0xffff;
    return SEG_U16(inertia_ss, inertia_esp & 0xffff);
}