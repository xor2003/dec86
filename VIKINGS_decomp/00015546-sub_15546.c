extern unsigned short g_0372;
void sub_1555c(void);

    extern unsigned short inertia_ds;
void sub_15546(void)
{

    unsigned short si;  // si
    SEG_U16(inertia_ds, 912) = 1;
    si = 0;
    do
    {
        sub_1555c();
        si += 2;
    } while (si + 2 < g_0372);
    return;
}