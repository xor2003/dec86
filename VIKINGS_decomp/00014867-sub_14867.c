int jpt_1DBFE(void);


extern unsigned long inertia_eax;
extern unsigned short g_008A;

    extern unsigned short xffff;
void sub_14867(void)
{
    inertia_eax = jpt_1DBFE();
    if (g_008A < (inertia_eax & 0xffff))
    {
        return;
    }
}