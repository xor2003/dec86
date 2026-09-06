extern unsigned long inertia_esp;

    extern unsigned short inertia_ds;
void sub_13d52(void)
{

    unsigned int d;  // d
    unsigned short si;  // si
    si = 0;
    while (1)
    {
        if (SEG_U16(inertia_ds, 4949 + si))
        {
            si += 2;
            if (si == 40)
            {
                inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
                return;
            }
        }
        else
        {
            inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
            return;
        }
    }
}