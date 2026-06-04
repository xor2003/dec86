enum TokenKind {
    TOK_ZERO,
    TOK_ONE,
    TOK_TWO,
    TOK_MANY
};

union IntBytes {
    unsigned short word;
    unsigned char bytes[2];
};

int token_cost(enum TokenKind kind)
{
    switch (kind) {
    case TOK_ZERO:
        return 0;
    case TOK_ONE:
        return 1;
    case TOK_TWO:
        return 2;
    default:
        return 9;
    }
}

unsigned short combine_bytes(unsigned char left, unsigned char right)
{
    union IntBytes value;

    value.bytes[0] = left;
    value.bytes[1] = right;
    return value.word;
}

int main(void)
{
    unsigned short combined;

    combined = combine_bytes(0x34, 0x12);
    if (token_cost(TOK_TWO) != 2) {
        return 1;
    }
    if (token_cost(TOK_MANY) != 9) {
        return 2;
    }
    if (combined != 0x1234) {
        return 3;
    }
    return 255;
}
