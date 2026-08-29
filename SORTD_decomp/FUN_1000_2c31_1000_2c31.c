
int __cdecl16near FUN_1000_2c31(void)

{
  int iVar1;
  uint uVar2;
  char extraout_DL;
  char cVar3;
  int extraout_DX;

  cVar3 = DAT_4000_d1bc;
  LOCK();
  DAT_4000_d1bc = 0;
  UNLOCK();
  if (cVar3 != '\0') {
    DAT_4000_d1dc = cVar3;
    iVar1 = FUN_1000_2c64();
    cVar3 = extraout_DL;
    if (extraout_DL == -1) {
      cVar3 = (char)iVar1;
    }
    if (cVar3 == (char)iVar1) {
      DAT_4000_d1dc = cVar3;
      return iVar1;
    }
  }
  uVar2 = 0;
  FUN_1000_33e6();
  DAT_4000_d1dc = (char)(extraout_DX + 1U);
  return (uVar2 & 0xff) * (extraout_DX + 1U & 0xff);
}
