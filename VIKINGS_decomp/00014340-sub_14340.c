unsigned short sub_15505(void);

extern unsigned long inertia_esp;

void sub_14340(void)
{

    unsigned int eax;  // eax
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    eax = sub_15505();
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}