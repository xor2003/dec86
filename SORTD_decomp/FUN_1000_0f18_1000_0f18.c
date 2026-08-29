
void FUN_1000_0f18(uint param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;

  FUN_1000_1222();
  uVar3 = FUN_1000_137e();
  iVar1 = (int)((ulong)uVar3 >> 0x10) + param_2 + (uint)CARRY2((uint)uVar3,param_1);
  do {
    uVar3 = FUN_1000_137e();
    iVar2 = (int)((ulong)uVar3 >> 0x10);
    if (iVar1 < iVar2) {
      return;
    }
  } while ((iVar2 < iVar1) || ((uint)uVar3 < 0xf56));
  return;
}
