
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

uint __cdecl16near FUN_1000_314b(void)

{
  uint in_AX;
  byte bVar1;
  byte in_BL;
  byte in_BH;

  if (((DAT_4000_d1dc == '\x19') && (_DAT_4000_d1df != 200)) &&
     ((_DAT_4000_d1d9 == 7 || (((DAT_4000_d745 & 0xc) == 0 || ((bRam00000487 & 1) != 0)))))) {
    bVar1 = (byte)(in_AX >> 8);
    in_AX = CONCAT11(bVar1 & 0x20 |
                     (byte)(((bVar1 & 0x1f) * (uint)in_BH + (uint)(in_BL >> 1)) / (uint)in_BL),
                     (char)(((in_AX & 0x1f) * (uint)in_BH + (uint)(in_BL >> 1)) / (uint)in_BL));
  }
  return in_AX & 0x3f1f;
}
