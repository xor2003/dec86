
int __cdecl16far FUN_1000_2a29(int param_1)

{
  int iVar1;
  char cVar2;
  undefined4 uVar3;

  if (param_1 != -1) {
    DAT_4000_d736 = 0xfc;
    if ((char)((uint)param_1 >> 8) != '\0') goto LAB_1000_2a74;
    param_1 = CONCAT11((char)param_1,(char)param_1);
  }
  LOCK();
  cVar2 = (char)((uint)param_1 >> 8);
  UNLOCK();
  if ((char)param_1 == DAT_4000_d1dc) {
    DAT_4000_d736 = 0;
    DAT_4000_d1dc = cVar2;
  }
  else {
    DAT_4000_d1dc = cVar2;
    uVar3 = FUN_1000_2c64();
    DAT_4000_d1dc = (char)((ulong)uVar3 >> 0x18);
    cVar2 = (char)((ulong)uVar3 >> 0x10);
    if ((cVar2 == -1) || (DAT_4000_d736 = 3, cVar2 == (char)uVar3)) {
      iVar1 = FUN_1000_2944(DAT_4000_d1d9,(uint)uVar3 & 0xff);
      return iVar1;
    }
  }
LAB_1000_2a74:
  return (int)DAT_4000_d1dc;
}
