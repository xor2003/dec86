long select_max(long a, long b)
{
    if (a >= b) {
        return a;
    }
    return b;
}

int compare_signed(long a, long b)
{
    if (a < b) {
        return -1;
    }
    if (a > b) {
        return 1;
    }
    if (a == b) {
        return 0;
    }
    return 2;
}

int compare_unsigned(unsigned long a, unsigned long b)
{
    if (a <= b) {
        return 3;
    }
    if (a >= b) {
        return 4;
    }
    return 5;
}

long clamp_window(long value, long low, long high)
{
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}

int main(void)
{
    long a;
    long b;
    unsigned long ua;
    unsigned long ub;
    long clipped;

    a = 100000L;
    b = -2000L;
    ua = 300000UL;
    ub = 300001UL;
    clipped = clamp_window(a, -100L, 50000L);
    return (int)select_max(a, b) + compare_signed(a, b) + compare_unsigned(ua, ub) + (int)clipped;
}
