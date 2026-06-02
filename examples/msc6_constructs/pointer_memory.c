void fill_bytes(unsigned char *dst, unsigned char value, int count)
{
    int i;

    for (i = 0; i < count; ++i) {
        dst[i] = value;
    }
}

int sum_words(const unsigned short *src, int count)
{
    int i;
    int total;

    total = 0;
    for (i = 0; i < count; ++i) {
        total += src[i];
    }
    return total;
}

void swap_ptrs(int *left, int *right)
{
    int tmp;

    tmp = *left;
    *left = *right;
    *right = tmp;
}

int main(void)
{
    unsigned char bytes[8];
    unsigned short words[4];
    int a;
    int b;

    fill_bytes(bytes, 3, 8);
    words[0] = 10;
    words[1] = 20;
    words[2] = 30;
    words[3] = 40;
    a = 5;
    b = 9;
    swap_ptrs(&a, &b);
    if (bytes[2] != 3) {
        return 1;
    }
    if (sum_words(words, 4) != 100) {
        return 2;
    }
    if (a != 9 || b != 5) {
        return 3;
    }
    return 0;
}
