
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int __cdecl16near FUN_1000_24c8(int param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;

  piVar3 = _DAT_4000_d2a1;
  if ((_DAT_4000_d2a1 != (int *)0x0) && (param_1 != 0)) {
    iVar1 = FUN_1000_2630(param_1);
    for (; *piVar3 != 0; piVar3 = piVar3 + 1) {
      iVar2 = FUN_1000_2630(*piVar3);
      if (((iVar1 < iVar2) && (*(char *)(*piVar3 + iVar1) == '=')) &&
         (iVar2 = FUN_1000_264c(*piVar3,param_1,iVar1), iVar2 == 0)) {
        return *piVar3 + iVar1 + 1;
      }
    }
  }
  return 0;
}
