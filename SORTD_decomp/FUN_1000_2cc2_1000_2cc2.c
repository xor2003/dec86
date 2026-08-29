
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_2cc2(void)

{
  undefined1 in_ZF;

  FUN_1000_33fa();
  if ((bool)in_ZF) {
    if (DAT_4000_d1dc != 0x19) {
      DAT_4000_d1e8 = DAT_4000_d1dc & 1 | 6;
      if (DAT_4000_d1db != '(') {
        DAT_4000_d1e8 = 3;
      }
      if (((DAT_4000_d745 & 4) != 0) && (_DAT_4000_d747 < 0x41)) {
        DAT_4000_d1e8 = DAT_4000_d1e8 >> 1;
      }
    }
    FUN_1000_3993();
  }
  return;
}
