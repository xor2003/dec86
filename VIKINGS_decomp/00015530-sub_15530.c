extern unsigned short g_0372;
void sub_15569(void);

    extern unsigned short inertia_ds;
void sub_15530(void)
{

    unsigned short si;  // si
    SEG_U16(inertia_ds, 912) = 0xffff;
    si = 0;
    do
    {
        sub_15569();
        si += 2;
    } while (si + 2 < g_0372);
    return;
}