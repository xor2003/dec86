extern unsigned long inertia_esp;

    extern unsigned short xffff;
    extern unsigned short inertia_ss;
void sub_151F2(void)
{
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    SEG_U8(inertia_ss, -2 + (inertia_esp & 0xffff)) = 0;
    SEG_U8(inertia_ss, -1 + (inertia_esp & 0xffff)) = 0;
}