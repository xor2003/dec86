
/* WARNING: Instruction at (ram,0x00012c85) overlaps instruction at (ram,0x00012c84)
    */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_2c64(void)

{
  byte bVar1;

  if (((_DAT_4000_d745 & 0x1c) != 0) && (DAT_4000_d1d9 != 0x40)) {
    bVar1 = *(byte *)(ulong)(DAT_4000_d1d9 + 0x1b8);
    if ((_DAT_4000_d745 & 8) == 0) {
      if ((_DAT_4000_d745 & 0x10) == 0) {
        bVar1 = bVar1 & 5;
      }
      else {
        bVar1 = bVar1 & 0x13;
      }
    }
    if (DAT_4000_d1dc == -1) {
      DAT_4000_d1dc = '<';
    }
    if (DAT_4000_d1dc == '<') {
      if ((bVar1 & 0x10) != 0) {
        DAT_4000_d1dc = 0x3c;
        return;
      }
      DAT_4000_d1dc = '2';
    }
    if (DAT_4000_d1dc == '2') {
      if ((bVar1 & 8) != 0) {
        DAT_4000_d1dc = 0x32;
        return;
      }
      DAT_4000_d1dc = '+';
    }
    if (((DAT_4000_d1dc == '+') && ((bVar1 & 4) != 0)) && ((_DAT_4000_d745 & 0x200) == 0)) {
      DAT_4000_d1dc = 0x2b;
      return;
    }
    if ((bVar1 & 2) != 0) {
      DAT_4000_d1dc = 0x1e;
      return;
    }
  }
  DAT_4000_d1dc = 0x19;
  return;
}
