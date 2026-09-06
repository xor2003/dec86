unsigned short sub_12e84(void);

extern unsigned long inertia_esp;
extern unsigned char g_25BA;

void sub_12e79(void)
{

    unsigned int eax;  // eax
    if (g_25BA & 0xff)
    {
        inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
        eax = sub_12e84();
    }
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return;
}