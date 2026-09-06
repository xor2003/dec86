extern unsigned long inertia_esp;
extern unsigned short g_A39C;

void sub_10130(void)
{

    do
    {
    } while (g_A39C >= 1);
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}
void sub_12ce4(void);

extern unsigned long inertia_esp;

    extern unsigned short inertia_ds;
void sub_108B8(void)
{
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    sub_12ce4();
    SEG_U16(inertia_ds, 9673) = 39;
    SEG_U16(inertia_ds, 962) = 0;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}
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
