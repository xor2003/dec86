struct Pair {
    int left;
    int right;
};

int accumulate_pairs(struct Pair *pairs, int count)
{
    int i;
    int total;

    total = 0;
    for (i = 0; i < count; ++i) {
        total += pairs[i].left * 2;
        total += pairs[i].right;
    }
    return total;
}

void rotate_triplet(int *values)
{
    int tmp;

    tmp = values[0];
    values[0] = values[1];
    values[1] = values[2];
    values[2] = tmp;
}

int find_first_gt(int *values, int count, int threshold)
{
    int i;

    i = 0;
    while (i < count) {
        if (values[i] > threshold) {
            return i;
        }
        ++i;
    }
    return -1;
}

int main(void)
{
    struct Pair pairs[3];
    int values[4];
    int total;
    int pos;

    pairs[0].left = 1;
    pairs[0].right = 3;
    pairs[1].left = 2;
    pairs[1].right = 5;
    pairs[2].left = 4;
    pairs[2].right = 7;

    values[0] = 4;
    values[1] = 8;
    values[2] = 15;
    values[3] = 16;

    rotate_triplet(values);
    total = accumulate_pairs(pairs, 3);
    pos = find_first_gt(values, 4, 10);
    if (values[0] != 8 || values[1] != 15 || values[2] != 4) {
        return 1;
    }
    if (total != 29) {
        return 2;
    }
    if (pos != 1) {
        return 3;
    }
    return 255;
}
