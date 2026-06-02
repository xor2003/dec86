int cmp_i16(int a, int b)
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

int rel_i16(int a, int b)
{
    int mask;

    mask = 0;
    if (a < b) {
        mask |= 1;
    }
    if (a <= b) {
        mask |= 2;
    }
    if (a > b) {
        mask |= 4;
    }
    if (a >= b) {
        mask |= 8;
    }
    if (a == b) {
        mask |= 16;
    }
    if (a != b) {
        mask |= 32;
    }
    return mask;
}

int rel_u16(unsigned int a, unsigned int b)
{
    int mask;

    mask = 0;
    if (a < b) {
        mask |= 1;
    }
    if (a <= b) {
        mask |= 2;
    }
    if (a > b) {
        mask |= 4;
    }
    if (a >= b) {
        mask |= 8;
    }
    if (a == b) {
        mask |= 16;
    }
    if (a != b) {
        mask |= 32;
    }
    return mask;
}

unsigned int clamp_u16(unsigned int value, unsigned int limit)
{
    if (value <= limit) {
        return value;
    }
    return limit;
}

int in_window_i16(int value, int low, int high)
{
    if (value < low) {
        return 0;
    }
    if (value > high) {
        return 0;
    }
    return 1;
}

int main(void)
{
    if (cmp_i16(-2, 5) != -1) {
        return 1;
    }
    if (cmp_i16(9, 3) != 1) {
        return 2;
    }
    if (cmp_i16(7, 7) != 0) {
        return 3;
    }
    if (rel_i16(-2, 5) != (1 | 2 | 32)) {
        return 4;
    }
    if (rel_i16(9, 3) != (4 | 8 | 32)) {
        return 5;
    }
    if (rel_i16(7, 7) != (2 | 8 | 16)) {
        return 6;
    }
    if (rel_u16(2U, 9U) != (1 | 2 | 32)) {
        return 7;
    }
    if (rel_u16(12U, 3U) != (4 | 8 | 32)) {
        return 8;
    }
    if (rel_u16(6U, 6U) != (2 | 8 | 16)) {
        return 9;
    }
    if (clamp_u16(10U, 7U) != 7U) {
        return 10;
    }
    if (clamp_u16(6U, 7U) != 6U) {
        return 11;
    }
    if (in_window_i16(4, 1, 7) != 1) {
        return 12;
    }
    if (in_window_i16(9, 1, 7) != 0) {
        return 13;
    }
    return 0;
}
