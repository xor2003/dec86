
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_3117(void)

{
  byte extraout_AL;
  byte bVar1;
  byte extraout_AH;
  byte bVar2;

  FUN_1000_314b();
  bVar1 = extraout_AL;
  if (6 < extraout_AL) {
    bVar1 = 7;
  }
  bVar2 = extraout_AH & 0x1f;
  if (6 < (extraout_AH & 0x1f)) {
    bVar2 = 7;
  }
  _DAT_4000_d1d4 = CONCAT11(bVar2 | extraout_AH & 0x20,bVar1);
  return;
}
