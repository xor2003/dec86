
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_235a(void)

{
  char cVar1;
  uint in_AX;

  DAT_4000_d285 = (byte)in_AX;
  cVar1 = (char)(in_AX >> 8);
  if (cVar1 != '\0') goto LAB_1000_237e;
  if (DAT_4000_d282 < 3) {
LAB_1000_2374:
    if (0x13 < DAT_4000_d285) {
LAB_1000_2378:
      in_AX = 0x13;
    }
  }
  else {
    if (0x21 < DAT_4000_d285) goto LAB_1000_2378;
    if (DAT_4000_d285 < 0x20) goto LAB_1000_2374;
    in_AX = 5;
  }
  cVar1 = *(char *)(ulong)((in_AX & 0xff) + 0x618);
LAB_1000_237e:
  _DAT_4000_d27a = (int)cVar1;
  return;
}
