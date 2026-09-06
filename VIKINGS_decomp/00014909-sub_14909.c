void sub_12312(void);

extern unsigned long inertia_eax;
extern unsigned short g_008A;

    extern unsigned short xffff;
void sub_14909(void)
{
    sub_12312();
    if (g_008A >= (inertia_eax & 0xffff))
    {
        return;
    }
}