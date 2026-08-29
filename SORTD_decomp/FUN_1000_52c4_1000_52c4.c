
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined2 __cdecl16near FUN_1000_52c4(void)

{
  undefined2 in_AX;
  int iVar1;
  int iVar2;

  iVar1 = _DAT_4000_d84e;
  iVar2 = 0;
  if (DAT_4000_d899 == '\0') {
    iVar1 = _DAT_4000_d854;
    iVar2 = _DAT_4000_d852;
  }
  _DAT_4000_d85e = iVar1 - iVar2;
  _DAT_4000_d862 = iVar2 + ((iVar1 - iVar2) + 1U >> 1);
  iVar1 = _DAT_4000_d850;
  iVar2 = 0;
  if (DAT_4000_d899 == '\0') {
    iVar1 = _DAT_4000_d858;
    iVar2 = _DAT_4000_d856;
  }
  _DAT_4000_d860 = iVar1 - iVar2;
  _DAT_4000_d864 = iVar2 + ((iVar1 - iVar2) + 1U >> 1);
  return in_AX;
}
