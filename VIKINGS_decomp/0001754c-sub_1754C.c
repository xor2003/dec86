unsigned short sub_1c22e(unsigned short a0, unsigned short a1);

extern unsigned long inertia_esp;
extern unsigned short g_A39A;

    extern unsigned short inertia_cs;
void sub_1754C(void)
{

    unsigned int eax;  // eax
    if (g_A39A & 0xffff)
    {
        inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
        inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
        inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 65538 - 65538 & 0xffff;
        inertia_cs = 7085;
        eax = sub_1c22e(0, 0);
        inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 4 & 0xffff;
    }
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}