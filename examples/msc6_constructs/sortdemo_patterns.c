unsigned short g_rows = 6;
unsigned short g_work[8] = { 9, 1, 5, 2, 8, 3, 7, 4 };
unsigned short g_demo_rows = 6;
unsigned short g_demo_len[6] = { 9, 1, 5, 2, 8, 3 };
unsigned short g_demo_bar[6] = { 0, 1, 2, 3, 4, 5 };
unsigned short g_demo_draw_calls = 0;
unsigned short g_demo_draw_last = 0;

void DrawTime(unsigned short row)
{
    g_demo_draw_calls = g_demo_draw_calls + 1;
    g_demo_draw_last = row;
}

void SwapBars(unsigned short left, unsigned short right)
{
    unsigned short tmp;

    tmp = g_demo_bar[left];
    g_demo_bar[left] = g_demo_bar[right];
    g_demo_bar[right] = tmp;
}

void Swaps(unsigned short *left, unsigned short *right)
{
    unsigned short tmp;

    tmp = *left;
    *left = *right;
    *right = tmp;
}

void sortdemo_reset_work(void)
{
    g_work[0] = 9;
    g_work[1] = 1;
    g_work[2] = 5;
    g_work[3] = 2;
    g_work[4] = 8;
    g_work[5] = 3;
    g_work[6] = 7;
    g_work[7] = 4;
}

int sortdemo_loop_bound(void)
{
    int i;
    int total;

    total = 0;
    for (i = 0; g_rows > (unsigned short)i; ++i) {
        total += i;
    }
    return total;
}

int sortdemo_descend_count(int max_level)
{
    int i;
    int total;

    total = 0;
    for (i = max_level; i != 0; --i) {
        total += i;
    }
    return total;
}

int sortdemo_global_pair_sum(void)
{
    return g_work[0] + g_work[5];
}

int sortdemo_adjacent_gt(int i)
{
    if (g_work[i - 1] > g_work[i]) {
        return 1;
    }
    return 0;
}

int sortdemo_adjacent_swap_once(int i)
{
    unsigned short tmp;

    if (g_work[i - 1] > g_work[i]) {
        tmp = g_work[i - 1];
        g_work[i - 1] = g_work[i];
        g_work[i] = tmp;
        return 1;
    }
    return 0;
}

int sortdemo_single_pass_swap(void)
{
    int i;
    int changed;
    unsigned short tmp;

    changed = 0;
    for (i = 1; g_rows > (unsigned short)i; ++i) {
        if (g_work[i - 1] > g_work[i]) {
            tmp = g_work[i - 1];
            g_work[i - 1] = g_work[i];
            g_work[i] = tmp;
            changed = 1;
        }
    }
    return changed + g_work[0] + g_work[5];
}

int sortdemo_switch_loop(void)
{
    int i;
    int changed;
    unsigned short tmp;

    do {
        changed = 0;
        for (i = 1; g_rows > (unsigned short)i; ++i) {
            if (g_work[i - 1] > g_work[i]) {
                tmp = g_work[i - 1];
                g_work[i - 1] = g_work[i];
                g_work[i] = tmp;
                changed = 1;
            }
        }
    } while (changed);
    return g_work[0] + g_work[5];
}

int sortdemo_pivot_scan(int low, int high)
{
    int up;
    int down;
    unsigned short pivot;

    up = low;
    down = high - 1;
    pivot = g_work[high];
    while (down > up) {
        while (down > up && g_work[up] <= pivot) {
            ++up;
        }
        while (down > up && g_work[down] >= pivot) {
            --down;
        }
        if (down > up) {
            pivot = g_work[up];
            g_work[up] = g_work[down];
            g_work[down] = pivot;
            ++up;
            --down;
            pivot = g_work[high];
        }
    }
    return up + down;
}

void sortdemo_exchangedata_init(void)
{
    g_demo_len[0] = 9;
    g_demo_len[1] = 1;
    g_demo_len[2] = 5;
    g_demo_len[3] = 2;
    g_demo_len[4] = 8;
    g_demo_len[5] = 3;
    g_demo_bar[0] = 0;
    g_demo_bar[1] = 1;
    g_demo_bar[2] = 2;
    g_demo_bar[3] = 3;
    g_demo_bar[4] = 4;
    g_demo_bar[5] = 5;
    g_demo_draw_calls = 0;
    g_demo_draw_last = 0;
}

int sortdemo_exchange_sort(void)
{
    unsigned short iRowCur;
    unsigned short iRowNext;
    unsigned short iRowMin;
    int iCompares;

    iCompares = 0;
    for (iRowCur = 0; g_demo_rows > iRowCur; ++iRowCur) {
        iRowMin = iRowCur;
        for (iRowNext = iRowCur; g_demo_rows > iRowNext; ++iRowNext) {
            ++iCompares;
            if (g_demo_len[iRowNext] < g_demo_len[iRowMin]) {
                iRowMin = iRowNext;
                DrawTime(iRowNext);
            }
        }
        if (iRowMin > iRowCur) {
            Swaps(&g_demo_len[iRowCur], &g_demo_len[iRowMin]);
            SwapBars(iRowCur, iRowMin);
        }
    }
    return iCompares;
}

void sortdemo_heap_percolate_up(int max_level)
{
    int i;
    int parent;

    i = max_level;
    while (i) {
        parent = i / 2;
        if (g_demo_len[i] > g_demo_len[parent]) {
            Swaps(&g_demo_len[i], &g_demo_len[parent]);
            SwapBars(i, parent);
        }
        i = parent;
    }
}

int main(void)
{
    if (sortdemo_loop_bound() != 15) {
        return 1;
    }
    if (sortdemo_descend_count(4) != 10) {
        return 2;
    }
    if (sortdemo_global_pair_sum() != 12) {
        return 3;
    }
    if (sortdemo_adjacent_gt(1) != 1) {
        return 4;
    }
    if (sortdemo_adjacent_gt(2) != 0) {
        return 5;
    }
    sortdemo_reset_work();
    if (sortdemo_single_pass_swap() != 11) {
        return 6;
    }
    if (g_work[0] != 1 || g_work[5] != 9) {
        return 7;
    }
    sortdemo_reset_work();
    if (sortdemo_switch_loop() != 10) {
        return 8;
    }
    if (g_work[0] != 1 || g_work[5] != 9) {
        return 9;
    }
    sortdemo_reset_work();
    if (sortdemo_pivot_scan(0, 5) != 4) {
        return 10;
    }
    if (g_work[0] != 2 || g_work[3] != 9) {
        return 11;
    }
    sortdemo_exchangedata_init();
    if (sortdemo_exchange_sort() != 21) {
        return 12;
    }
    if (g_demo_len[0] != 1 || g_demo_len[5] != 9) {
        return 13;
    }
    if (g_demo_bar[0] != 1 || g_demo_bar[5] != 0) {
        return 14;
    }
    if (g_demo_draw_calls != 6 || g_demo_draw_last != 5) {
        return 15;
    }
    sortdemo_exchangedata_init();
    sortdemo_heap_percolate_up(4);
    if (g_demo_len[1] != 8 || g_demo_len[2] != 1 || g_demo_len[4] != 5) {
        return 16;
    }
    if (g_demo_bar[1] != 4 || g_demo_bar[2] != 1 || g_demo_bar[4] != 2) {
        return 17;
    }
    return 255;
}
