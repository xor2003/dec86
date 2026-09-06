extern unsigned long inertia_esp;
extern unsigned long inertia_esi;
extern unsigned long inertia_edi;
extern unsigned short g_006C;

    extern unsigned short xffff;
    extern unsigned short xffff0000;
    extern unsigned short inertia_ss;
    extern unsigned short inertia_ds;
void sub_15ae9(void)
{
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    SEG_U8(inertia_ss, -2 + (inertia_esp & 0xffff)) = inertia_esi & 0xffff;
    SEG_U8(inertia_ss, -1 + (inertia_esp & 0xffff)) = (inertia_esi & 0xffff) >> 8;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    SEG_U8(inertia_ss, -2 + (inertia_esp & 0xffff)) = inertia_edi & 0xffff;
    SEG_U8(inertia_ss, -1 + (inertia_esp & 0xffff)) = (inertia_edi & 0xffff) >> 8;
    SEG_U16(inertia_ds, 52) = g_006C;
    inertia_esi = inertia_esi & 0xffff0000 | g_006C & 0xffff;
}