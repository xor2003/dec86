void sub_16ded(void);

extern unsigned long inertia_esp;
extern unsigned char g_25CF;

void sub_11439(void)
{

    if (!(g_25CF & 66))
    {
        inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
        sub_16ded();
    }
}