unsigned short sub_12312(void);

extern unsigned long inertia_esp;

    extern unsigned short inertia_ds;
unsigned short sub_14b67(void)
{

    unsigned short tmp_0;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
    tmp_0 = sub_12312();
    SEG_U16(inertia_ds, 138) = tmp_0 & 1;
    inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) + 2 & 0xffff;
    return tmp_0 & 1;
}