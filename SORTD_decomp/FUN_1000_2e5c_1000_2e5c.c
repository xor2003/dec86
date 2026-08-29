
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near
FUN_1000_2e5c(undefined2 param_1,undefined2 *param_2,undefined2 param_3,undefined2 param_4,
             undefined2 param_5)

{
  code *pcVar1;
  ulong uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  uint *puVar6;
  uint *puVar7;

  FUN_1000_2efb();
  if (DAT_4000_d1d8 < 3) {
    uRam0000007c = 0x1ce;
    uRam0000007e = 0x4cff;
  }
  else if (_DAT_4000_d1d9 == 0x13) {
    (*_DAT_4000_d20e)();
    uVar3 = CONCAT11(DAT_4000_d77d,DAT_4000_d77d);
    uVar2 = (ulong)_DAT_4000_d74c >> 0x10;
    puVar6 = (uint *)_DAT_4000_d74c;
    iVar4 = 8;
    do {
      iVar5 = 4;
      do {
        puVar7 = puVar6;
        *puVar7 = *puVar7 ^ uVar3;
        iVar5 = iVar5 + -1;
        puVar6 = puVar7 + 1;
      } while (iVar5 != 0);
      puVar6 = puVar7 + 0x9d;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    return;
  }
  pcVar1 = (code *)swi(0x10);
  (*pcVar1)();
  if (DAT_4000_d1d8 < 3) {
    *param_2 = param_4;
    param_2[1] = param_5;
  }
  return;
}
