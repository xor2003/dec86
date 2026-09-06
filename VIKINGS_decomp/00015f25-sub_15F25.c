extern unsigned long inertia_ebx;

void sub_15F25(void)
{

    inertia_ebx = inertia_ebx & 0xffff0000 | (inertia_ebx & 0xffff) - 1 & 0xffff;
}