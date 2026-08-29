
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_0672(void)

{
  undefined4 uVar1;
  int iVar2;

  FUN_1000_1222();
  uVar1 = FUN_1000_137e();
  for (iVar2 = 0; _DAT_4000_db98 = (undefined2)((ulong)uVar1 >> 0x10),
      _DAT_4000_db96 = (undefined2)uVar1, iVar2 < _DAT_4000_db92; iVar2 = iVar2 + 1) {
    _DAT_4000_db96 = uVar1;
    *(undefined2 *)(iVar2 * 2 + 0xb4c) = *(undefined2 *)(iVar2 * 2 + 0x8f0);
    FUN_1000_06c8(iVar2);
    uVar1 = _DAT_4000_db96;
  }
  return;
}
