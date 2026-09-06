extern unsigned long inertia_ebx;
extern unsigned long inertia_esp;

unsigned short sub_1547e(void)
{

    inertia_ebx = inertia_ebx & 0xffff0000 | (inertia_ebx & 0xffff) + 2 & 0xffff;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return SEG_U16(inertia_es, inertia_ebx & 0xffff);
}