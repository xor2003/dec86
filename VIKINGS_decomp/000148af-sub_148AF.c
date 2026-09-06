void sub_ffffea63(void);


extern unsigned long inertia_eax;
extern unsigned short g_008A;

    extern unsigned short xffff;
void sub_148AF(void)
{
    sub_ffffea63();
    if (g_008A < (inertia_eax & 0xffff))
    {
        return;
    }
}