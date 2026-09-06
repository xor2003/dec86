void sub_139ef(void);

extern unsigned long inertia_esp;

void sub_13A0E(void)
{
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    sub_139ef();
}