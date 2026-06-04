int classify(int x)
{
    if (x < 0) {
        return -1;
    }
    if (x == 0) {
        return 0;
    }
    if (x < 10) {
        return 1;
    }
    return 2;
}

int sum_to(int limit)
{
    int i;
    int total;

    total = 0;
    for (i = 0; i < limit; ++i) {
        if ((i & 1) == 0) {
            total += i;
        } else {
            total -= 1;
        }
    }
    return total;
}

int switch_fold(int x)
{
    switch (x) {
    case 0:
        return 10;
    case 1:
    case 2:
        return x + 20;
    case 3:
        return x * 2;
    default:
        return x - 5;
    }
}

int main(void)
{
    int a;
    int b;
    int c;

    a = classify(7);
    b = sum_to(6);
    c = switch_fold(2);
    if (classify(-4) != -1) {
        return 1;
    }
    if (classify(0) != 0) {
        return 2;
    }
    if (a != 1) {
        return 3;
    }
    if (b != 3) {
        return 4;
    }
    if (c != 22) {
        return 5;
    }
    return 255;
}
