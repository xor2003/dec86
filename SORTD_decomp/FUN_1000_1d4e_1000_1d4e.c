
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_1d4e(undefined2 *param_1)

{
  undefined2 uVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined1 local_1e [4];
  uint local_1a;
  uint local_18;
  int local_16;
  int local_14;
  int local_10;
  byte local_c;
  char local_b;
  undefined1 local_a;
  byte local_9;
  byte local_8;
  byte local_7;
  int local_6;

  FUN_1000_2188();
  uVar1 = FUN_1000_143a(_DAT_4000_d5c2,_DAT_4000_d5c4,0x3c,0);
  param_1[3] = uVar1;
  FUN_1000_22fe(&local_8);
  FUN_1000_2318(&local_c);
  if ((local_c == 0) && (local_b == '\0')) {
    FUN_1000_22fe(&local_8);
  }
  local_14 = local_6 + -0x76c;
  local_18 = (uint)local_8;
  uVar3 = (uint)local_7;
  local_16 = uVar3 - 1;
  local_10 = local_18 + *(int *)(local_16 * 2 + 0x5ac);
  if (((local_6 - 0x7bcU & 3) == 0) && (2 < uVar3)) {
    local_10 = local_10 + 1;
  }
  local_1a = (uint)local_c;
  param_1[2] = (uint)local_9 * 10;
  uVar4 = FUN_1000_1e42(local_6 - 0x7bcU,uVar3,local_18,local_c,local_b,local_a);
  *param_1 = (int)uVar4;
  param_1[1] = (int)((ulong)uVar4 >> 0x10);
  if ((_DAT_4000_d5c6 != 0) && (iVar2 = FUN_1000_2234(local_1e), iVar2 != 0)) {
    param_1[4] = 1;
    return;
  }
  param_1[4] = 0;
  return;
}
