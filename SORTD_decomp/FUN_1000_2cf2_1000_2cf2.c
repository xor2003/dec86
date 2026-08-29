
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int __cdecl16near FUN_1000_2cf2(void)

{
  int iVar1;
  undefined1 in_ZF;

  FUN_1000_33fa();
  if (!(bool)in_ZF) {
    FUN_1000_530b();
    _DAT_4000_d774 = _DAT_4000_d862;
    _DAT_4000_d776 = _DAT_4000_d864;
    _DAT_4000_d77e = 0xffff;
    DAT_4000_d73f = 3;
    if (DAT_4000_d1d8 == '\x01') {
      FUN_1000_3034();
    }
  }
  _DAT_4000_d778 = 0;
  _DAT_4000_d77a = 0;
  FUN_1000_2fd1();
  _DAT_4000_d7a1 = 0;
  _DAT_4000_d79f = 0;
  DAT_4000_d7a7 = 0;
  DAT_4000_d7a9 = 0;
  DAT_4000_d788 = 0;
  DAT_4000_d737 = 0;
  DAT_4000_d7a8 = 1;
  _DAT_4000_d7a5 = DAT_4000_d1db - 1;
  iVar1 = CONCAT11((char)(DAT_4000_d1db - 1 >> 8),DAT_4000_d1dc);
  _DAT_4000_d7a3 = iVar1 + -1;
  return iVar1;
}
