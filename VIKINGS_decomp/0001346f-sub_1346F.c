extern unsigned long inertia_esp;

unsigned short sub_1346f(void)
{
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 + 2 & 0xffff;
    return SEG_U16(inertia_ss, inertia_esp & 0xffff);
}