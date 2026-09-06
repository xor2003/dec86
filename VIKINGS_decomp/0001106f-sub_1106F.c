signed char sub_1106f(void)
{

    char al;  // al
    unsigned short cx;  // cx
    unsigned int d;  // d
    unsigned short dx;  // dx
    inertia_io_out8(968, 0);
    dx = 969;
    cx = 0x300;
    al = 0;
    do
    {
        inertia_io_out8(dx, al);
        cx -= 1;
    } while (cx);
    return 0;
}