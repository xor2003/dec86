
undefined1 __cdecl16near FUN_1000_2fd1(void)

{
  undefined1 uVar1;
  uint in_AX;
  byte bVar2;

  uVar1 = DAT_4000_d77c;
  if ((char)(in_AX >> 8) == '\0') {
    bVar2 = DAT_4000_d1e3;
    if (DAT_4000_d1d8 == '\0') {
      bVar2 = 0x1f;
    }
    if ((byte)in_AX <= bVar2) goto LAB_1000_2ff0;
  }
  in_AX = (uint)DAT_4000_d1e3;
  DAT_4000_d736 = 3;
LAB_1000_2ff0:
  LOCK();
  DAT_4000_d77c = (undefined1)in_AX;
  UNLOCK();
  FUN_1000_2ffa();
  return uVar1;
}
