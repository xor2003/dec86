extern unsigned long inertia_esp;

unsigned short sub_1346d(void)
{
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 + 2 & 0xffff;
}