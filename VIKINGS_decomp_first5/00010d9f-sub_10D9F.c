unsigned short dos_int21(void);

unsigned short sub_10dba(void);

short sub_10D9F(void)
{

    unsigned short ax;  // ax
    unsigned short flags;  // flags
    unsigned short flags_2;  // flags
    unsigned short ax_2;  // ax
    ax = dos_int21();
    flags = dos_int21_flags();
    if (!(flags & 1))
    {
        return ax;
    }
    sub_10dba();
    ax_2 = dos_int21();
    flags_2 = dos_int21_flags();
    if (!(flags_2 & 1))
        return ax_2;
}