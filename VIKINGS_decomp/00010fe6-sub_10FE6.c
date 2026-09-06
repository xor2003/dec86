extern long inertia_direction;

    extern unsigned short inertia_ds;
signed char sub_10fe6(void)
{

    unsigned short cx;  // cx
    unsigned int d;  // d
    unsigned short dx;  // dx
    unsigned short si;  // si
    unsigned short tmp_8;
    unsigned short tmp_14;
    unsigned short tmp_16;
    unsigned short tmp_17;
    SEG_U16(inertia_ds, 32510) = 0;
    si = 33282;
    inertia_io_out8(968, 0);
    d = inertia_direction;
    dx = 969;
    cx = 0x300;
    do
    {
        if (!cx)
            break;
        cx -= 1;
        tmp_8 = dx;
        tmp_14 = SEG_U8(inertia_ds, si);
        inertia_io_out8(tmp_8, tmp_14);
        tmp_16 = d;
        tmp_17 = tmp_16;
        si += tmp_17;
    } while (cx);
    return 0;
}