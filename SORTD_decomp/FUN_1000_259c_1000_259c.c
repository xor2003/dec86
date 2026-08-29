
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int FUN_1000_259c(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int local_4;

  iVar3 = 0;
  local_4 = 0;
  for (uVar2 = 0x43e; uVar2 <= _DAT_4000_d56e; uVar2 = uVar2 + 8) {
    if ((*(byte *)(uVar2 + 6) & 0x83) != 0) {
      iVar1 = FUN_1000_2522(uVar2);
      if (iVar1 == -1) {
        local_4 = -1;
      }
      else {
        iVar3 = iVar3 + 1;
      }
    }
  }
  if (param_1 == 1) {
    local_4 = iVar3;
  }
  return local_4;
}
