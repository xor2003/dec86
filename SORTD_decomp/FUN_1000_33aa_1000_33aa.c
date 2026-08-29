
void __cdecl16near FUN_1000_33aa(void)

{
  uint uVar1;

  if (DAT_4000_d745 == '\b') {
    uVar1 = CONCAT11(bRam00000410,DAT_4000_d1d9) & 0xff07;
    bRam00000410 = (byte)(uVar1 >> 8) | 0x30;
    if ((char)uVar1 != '\a') {
      bRam00000410 = bRam00000410 & 0xef;
    }
    DAT_4000_d742 = bRam00000410;
    if ((DAT_4000_d743 & 4) == 0) {
      FUN_1000_33e6();
    }
  }
  return;
}
