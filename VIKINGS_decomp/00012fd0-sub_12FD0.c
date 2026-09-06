void sub_12fe5(void);

extern unsigned short inertia_flags;
extern unsigned short g_0372;

    extern unsigned short x800;
void sub_12fd0(void)
{
    unsigned short iter;  // di
    unsigned short v11;  // flags
    unsigned short v12;  // 4117
    unsigned short v13;  // 4117
    unsigned short v4;  // flags
    unsigned short v7;  // 4117
    unsigned short v8;  // 4132
    unsigned short v9;  // 4137
    unsigned short v10;  // 4145
    unsigned char v6;  // 4112

    v4 = inertia_flags;
    v11 = inertia_flags;
    iter = g_0372 - 2;
    do
    {
        sub_12fe5();
        v6 = iter - 2 ^ iter - 2 >> 4 ^ (iter - 2 ^ iter - 2 >> 4) >> 2 ^ (iter - 2 ^ iter - 2 >> 4 ^ (iter - 2 ^ iter - 2 >> 4) >> 2) >> 1;
        v7 = (~(iter - 2 ^ iter - 2 >> 4 ^ (iter - 2 ^ iter - 2 >> 4) >> 2 ^ (iter - 2 ^ iter - 2 >> 4 ^ (iter - 2 ^ iter - 2 >> 4) >> 2) >> 1) & 1 & 1) << 2;
        v8 = 0 | (iter < 2 & 1) << 0 | (~(v6) & 1 & 1) << 2 | ((iter ^ 2 ^ iter - 2) >> 4 & 1 & 1) << 4 | (!(iter - 2) & 1) << 6;
        v9 = (1 & iter - 2 >> 15 & 1) << 7;
        v10 = ((iter ^ 2) & (iter ^ iter - 2)) >> 15 & 1 & 1;
        v11 = v4 & 63274 | (0 | (iter < 2 & 1) << 0 | v7 | ((iter ^ 2 ^ iter - 2) >> 4 & 1 & 1) << 4 | (!(iter - 2) & 1) << 6 | (1 & iter - 2 >> 15 & 1) << 7 | (((iter ^ 2) & (iter ^ iter - 2)) >> 15 & 1 & 1) << 11) & 2261;
        if ((v4 & 63274 | (v8 | v9 | v10 * 0x800) & 2261) >> 10 & 1 & 1)
        {
            v12 = (~(iter - 2 ^ iter - 2 >> 4 ^ (iter - 2 ^ iter - 2 >> 4) >> 2 ^ (iter - 2 ^ iter - 2 >> 4 ^ (iter - 2 ^ iter - 2 >> 4) >> 2) >> 1) & 1 & 1) << 2;
            v4 = v11 & 63274 | (0 | (iter < 2 & 1) << 0 | v12 | ((iter ^ 2 ^ iter - 2) >> 4 & 1 & 1) << 4 | (!(iter - 2) & 1) << 6 | (1 & iter - 2 >> 15 & 1) << 7 | (((iter ^ 2) & (iter ^ iter - 2)) >> 15 & 1 & 1) << 11) & 2261;
            iter -= 2;
        }
        else
        {
            v13 = (~(iter - 2 ^ iter - 2 >> 4 ^ (iter - 2 ^ iter - 2 >> 4) >> 2 ^ (iter - 2 ^ iter - 2 >> 4 ^ (iter - 2 ^ iter - 2 >> 4) >> 2) >> 1) & 1 & 1) << 2;
            v4 = v11 & 63274 | (0 | (iter < 2 & 1) << 0 | v13 | ((iter ^ 2 ^ iter - 2) >> 4 & 1 & 1) << 4 | (!(iter - 2) & 1) << 6 | (1 & iter - 2 >> 15 & 1) << 7 | (((iter ^ 2) & (iter ^ iter - 2)) >> 15 & 1 & 1) << 11) & 2261;
            iter -= 2;
        }
    } while (!(!(v4 & 128) ? 0 : 1));
    return;
}