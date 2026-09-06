extern unsigned long inertia_esp;

    extern unsigned short inertia_ds;
void sub_11383(void)
{

    unsigned int d;  // d
    unsigned short di;  // di
    di = 0;
    while (SEG_U16(inertia_ds, 9718 + di) != 0xffff)
    {
        di += 14;
    }
    di += 2;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}