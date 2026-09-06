extern unsigned long inertia_esp;
extern unsigned long inertia_edi;

    extern unsigned short xffff;
void sub_1237f(void)
{

    int cx;  // cx
    do
    {
        cx = 0x100;
        do
        {
            cx -= 1;
        } while (cx);
        inertia_edi = inertia_edi & 0xffff0000 | (inertia_edi & 0xffff) - 1 & 0xffff;
    } while ((inertia_edi & 0xffff) != 1);
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}