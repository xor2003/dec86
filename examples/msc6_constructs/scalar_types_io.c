signed char add_sc(signed char a, signed char b)
{
    return (signed char)(a + b);
}

unsigned char mix_uc(unsigned char a, unsigned char b)
{
    return (unsigned char)((a << 1) ^ b);
}

short sub_ss(short a, short b)
{
    return (short)(a - b);
}

unsigned short mul_us(unsigned short a, unsigned short b)
{
    return (unsigned short)(a * b);
}

int add_int(int a, int b)
{
    return a + b;
}

unsigned int rot_ui(unsigned int a)
{
    return (a << 1) | (a >> 15);
}

long add_long(long a, long b)
{
    return a + b;
}

unsigned long sub_ulong(unsigned long a, unsigned long b)
{
    return a - b;
}

float scale_float(float a, float b)
{
    return a * b + 1.0f;
}

double blend_double(double a, double b)
{
    return a / 2.0 + b;
}

char *pick_ptr(char *a, char *b, int which)
{
    if (which != 0) {
        return a;
    }
    return b;
}

int main(void)
{
    char text1[4];
    char text2[4];
    char *picked;
    int total;

    text1[0] = 'A';
    text1[1] = 0;
    text2[0] = 'B';
    text2[1] = 0;
    picked = pick_ptr(text1, text2, 0);
    total = add_sc(1, 2);
    total += mix_uc(7, 3);
    total += sub_ss(9, 4);
    total += mul_us(3, 5);
    total += add_int(10, 20);
    total += rot_ui(9U);
    total += (int)add_long(1000L, 2000L);
    total += (int)sub_ulong(90UL, 30UL);
    total += (int)scale_float(2.0f, 3.0f);
    total += (int)blend_double(8.0, 4.0);
    return total + picked[0];
}
