
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_09e8(int param_1)

{
  int iVar1;
  int iVar2;

  FUN_1000_1222();
  while( true ) {
    if (param_1 == 0) {
      return;
    }
    iVar1 = param_1 / 2;
    _DAT_4000_db9a = _DAT_4000_db9a + 1;
    if (*(char *)(param_1 * 2 + 0xb4c) <= *(char *)(iVar1 * 2 + 0xb4c)) break;
    iVar2 = param_1 * 2 + 0xb4c;
    FUN_1000_0794(iVar1 * 2 + 0xb4c,iVar2);
    FUN_1000_075b(iVar1,iVar2);
    param_1 = iVar1;
  }
  return;
}
