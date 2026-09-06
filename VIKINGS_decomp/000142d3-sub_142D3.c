extern unsigned long inertia_esp;

void sub_142d3(void)
{

    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}