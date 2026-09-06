unsigned short sub_141ba(void);

extern unsigned long inertia_esp;

unsigned short sub_141b3(void)
{

    unsigned short tmp_0;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    tmp_0 = sub_141ba();
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return tmp_0 & 0x3ff;
}