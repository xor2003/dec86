
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

long __cdecl16near
FUN_1000_1e42(int param_1,int param_2,int param_3,uint param_4,uint param_5,int param_6)

{
  int iVar1;
  uint uVar2;
  long lVar3;
  undefined4 uVar4;
  long lVar5;
  undefined2 uVar6;
  undefined2 uVar7;
  undefined2 uVar8;
  undefined2 uVar9;
  undefined1 local_14 [4];
  uint local_10;
  int local_c;
  int local_a;
  int local_6;

  iVar1 = (param_1 + 3) / 4;
  lVar3 = FUN_1000_1f38(iVar1,iVar1 >> 0xf,0x5180,1);
  iVar1 = *(int *)(param_2 * 2 + 0x5aa);
  if ((param_1 % 4 == 0) && (2 < param_2)) {
    iVar1 = iVar1 + 1;
  }
  local_6 = param_3 + iVar1;
  FUN_1000_2188();
  uVar9 = 0;
  uVar8 = 0x3c;
  uVar7 = 0;
  uVar6 = 0x3c;
  uVar2 = param_1 * 0x16d + param_3 + iVar1;
  uVar4 = FUN_1000_1f38(uVar2 + 0xe44,((int)uVar2 >> 0xf) + (uint)(0xf1bb < uVar2),0x18,0);
  uVar4 = FUN_1000_1f38(param_4 + (uint)uVar4,
                        ((int)param_4 >> 0xf) + (int)((ulong)uVar4 >> 0x10) +
                        (uint)CARRY2(param_4,(uint)uVar4),uVar6,uVar7);
  lVar5 = FUN_1000_1f38(param_5 + (uint)uVar4,
                        ((int)param_5 >> 0xf) + (int)((ulong)uVar4 >> 0x10) +
                        (uint)CARRY2(param_5,(uint)uVar4),uVar8,uVar9);
  lVar3 = lVar3 + param_6 + lVar5 + CONCAT22(_DAT_4000_d5c4,_DAT_4000_d5c2);
  local_a = param_1 + 0x50;
  local_c = param_2 + -1;
  local_10 = param_4;
  if (_DAT_4000_d5c6 != 0) {
    iVar1 = FUN_1000_2234(local_14);
    if (iVar1 != 0) {
      lVar3 = CONCAT22((int)((ulong)lVar3 >> 0x10) - (uint)((uint)lVar3 < 0xe10),(uint)lVar3 - 0xe10
                      );
    }
  }
  return lVar3;
}
