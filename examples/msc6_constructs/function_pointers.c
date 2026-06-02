int inc_one(int value)
{
    return value + 1;
}

int dec_one(int value)
{
    return value - 1;
}

int apply_twice(int (*fn)(int), int value)
{
    value = fn(value);
    value = fn(value);
    return value;
}

int select_and_apply(int which, int value)
{
    int (*fn)(int);

    if (which != 0) {
        fn = inc_one;
    } else {
        fn = dec_one;
    }
    return apply_twice(fn, value);
}

int main(void)
{
    return select_and_apply(1, 5) + select_and_apply(0, 8);
}
