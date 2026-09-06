extern unsigned long inertia_esp;

    extern unsigned short inertia_ds;
void sub_11192(void)
{

    unsigned short si;  // si
    si = 0;
    do
    {
        SEG_U8(inertia_ds, 854 + si) = 0;
        si += 1;
    } while (si < 16);
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}