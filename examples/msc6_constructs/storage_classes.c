static int g_counter = 3;
static unsigned char g_table[4] = { 1, 2, 3, 4 };

static int bump_static(void)
{
    static int seen = 10;

    seen += 2;
    return seen;
}

int sum_globals(void)
{
    int i;
    int total;

    total = g_counter;
    for (i = 0; i < 4; ++i) {
        total += g_table[i];
    }
    return total;
}

int main(void)
{
    int total;

    total = sum_globals();
    total += bump_static();
    total += bump_static();
    return total;
}
