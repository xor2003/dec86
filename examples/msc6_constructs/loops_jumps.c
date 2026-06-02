int nested_loops(int limit)
{
    int i;
    int j;
    int total;

    total = 0;
    i = 0;
    while (i < limit) {
        j = 0;
        do {
            if (j == i) {
                ++j;
                continue;
            }
            total += i + j;
            if (total > 40) {
                break;
            }
            ++j;
        } while (j < limit);
        if (total > 40) {
            break;
        }
        ++i;
    }
    return total;
}

int goto_accumulate(int x)
{
    int total;

    total = 0;
start:
    if (x <= 0) {
        return total;
    }
    total += x;
    --x;
    if ((x & 1) != 0) {
        goto start;
    }
    total += 2;
    goto start;
}

int main(void)
{
    if (nested_loops(5) != 42) {
        return 1;
    }
    if (goto_accumulate(4) != 12) {
        return 2;
    }
    return 0;
}
