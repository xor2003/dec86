extern unsigned long inertia_ebx;
extern unsigned long inertia_esp;

void sub_13674(void)
{

    inertia_ebx = inertia_ebx & 0xffff0000 | (inertia_ebx & 0xffff) + 1 & 0xffff;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}