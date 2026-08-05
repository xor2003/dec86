#include <stdint.h>
#include <string.h>

uint8_t inertia_memory[65536];
uint16_t inertia_cs;
uint16_t inertia_ds;
uint16_t inertia_es;
uint16_t inertia_ss;

void sub_10768(unsigned short first, unsigned short second)
{
    (void)first;
    (void)second;
}

void sub_10498(unsigned short row)
{
    (void)row;
}

void sub_106c8(unsigned short row)
{
    (void)row;
}

int sub_10794(unsigned short first, unsigned short second)
{
    uint16_t temporary;

    temporary = *(uint16_t *)&inertia_memory[first];
    *(uint16_t *)&inertia_memory[first] = *(uint16_t *)&inertia_memory[second];
    *(uint16_t *)&inertia_memory[second] = temporary;
    return 0;
}

void sub_107b8(unsigned short *left, unsigned short *right);
void sub_10808(void);
void sub_108d0(void);
void sub_10970(void);
void sub_109e8(unsigned short maximum);
void sub_10a88(short maximum);
void sub_10b50(void);
void sub_10c18(void);
void sub_10ce0(short low, short high);

int sub_10a61(unsigned short maximum)
{
    sub_10a88((short)maximum);
    return 0;
}

static void set_rows(int a, int b, int c, int d, int e)
{
    static const int colors[5] = {1, 2, 3, 4, 5};
    const int lengths[5] = {a, b, c, d, e};
    int index;

    memset(inertia_memory, 0, sizeof(inertia_memory));
    *(uint16_t *)&inertia_memory[0x0BA2] = 5;
    for (index = 0; index < 5; ++index) {
        inertia_memory[0x0B4C + index * 2] = (uint8_t)lengths[index];
        inertia_memory[0x0B4D + index * 2] = (uint8_t)colors[index];
    }
}

static int lengths_equal(int a, int b, int c, int d, int e)
{
    const int expected[5] = {a, b, c, d, e};
    int index;

    for (index = 0; index < 5; ++index) {
        if (inertia_memory[0x0B4C + index * 2] != expected[index])
            return 0;
    }
    return 1;
}

static int sorted(void)
{
    int index;

    for (index = 1; index < 5; ++index) {
        if (inertia_memory[0x0B4C + (index - 1) * 2] >
            inertia_memory[0x0B4C + index * 2])
            return 0;
    }
    return 1;
}

int main(void)
{
    set_rows(5, 3, 4, 1, 2);
    sub_107b8(
        (unsigned short *)&inertia_memory[0x0B4C],
        (unsigned short *)&inertia_memory[0x0B4E]);
    if (!lengths_equal(3, 5, 4, 1, 2))
        return 1;

    set_rows(3, 1, 2, 4, 5);
    sub_109e8(3);
    if (!lengths_equal(4, 3, 2, 1, 5))
        return 2;

    set_rows(1, 5, 4, 3, 2);
    sub_10a88(4);
    if (!lengths_equal(5, 4, 2, 3, 1))
        return 3;

    set_rows(4, 2, 5, 3, 1);
    sub_10808();
    if (!sorted())
        return 4;

    set_rows(4, 1, 5, 3, 2);
    sub_108d0();
    if (!sorted())
        return 5;

    set_rows(5, 1, 4, 2, 3);
    sub_10970();
    if (!sorted())
        return 6;

    set_rows(5, 4, 3, 2, 1);
    sub_10b50();
    if (!sorted())
        return 7;

    set_rows(5, 3, 4, 1, 2);
    sub_10c18();
    if (!sorted())
        return 8;

    set_rows(2, 5, 1, 4, 3);
    sub_10ce0(0, 4);
    if (!sorted())
        return 9;

    return 0;
}
