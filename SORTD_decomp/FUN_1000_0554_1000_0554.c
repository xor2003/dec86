
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_0554(void)

{
  int iVar1;
  int iVar2;
  undefined2 unaff_SS;
  int in_stack_00000bb8;
  int local_76;
  undefined1 local_74;
  undefined1 local_72 [14];
  int local_64;
  int local_60;
  int aiStack_5c [40];
  undefined2 uStack_c;
  undefined2 uStack_a;
  undefined1 *puStack_8;
  int iVar3;

  FUN_1000_1222();
  puStack_8 = (undefined1 *)0x572;
  FUN_1000_132c();
  puStack_8 = (undefined1 *)0x579;
  FUN_1000_1402();
  _DAT_4000_db36 = 1;
  _DAT_4000_d122 = 0x1e;
  _DAT_4000_d124 = 0;
  puStack_8 = local_72;
  uStack_a = 0x1000;
  uStack_c = 0x598;
  FUN_1000_2ac8();
  if (((local_60 == 1) || (local_64 == 2)) || (local_64 == 0)) {
    local_76 = 1;
  }
  else {
    local_76 = 0xf;
  }
  for (iVar3 = 0; iVar3 < _DAT_4000_db92; iVar3 = iVar3 + 1) {
    aiStack_5c[iVar3] = iVar3 + 1;
  }
  for (iVar3 = 0; iVar3 < _DAT_4000_db92; iVar3 = iVar3 + 1) {
    iVar2 = FUN_1000_1414();
    iVar1 = aiStack_5c[iVar2 % 0x60b];
    aiStack_5c[iVar2 % 0x60b] = in_stack_00000bb8;
    local_74 = (undefined1)iVar1;
    *(undefined1 *)(iVar3 * 2 + 0x8f0) = local_74;
    if (local_76 == 1) {
      *(undefined1 *)(iVar3 * 2 + 0x8f1) = 7;
    }
    else {
      *(char *)(iVar3 * 2 + 0x8f1) = (char)(iVar1 % local_76) + '\x01';
    }
  }
  FUN_1000_0672();
  return;
}
