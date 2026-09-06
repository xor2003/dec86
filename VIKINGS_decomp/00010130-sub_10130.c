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