extern unsigned short g_008A;
unsigned short sub_12312(void);

unsigned short sub_14e24(void)
{

    unsigned short v3;  // ax
    v3 = sub_12312();
    if (v3 == g_008A)
    {
        return v3 & 1 & 1;
    }
}