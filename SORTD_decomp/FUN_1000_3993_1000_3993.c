
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_3993(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;

  if (DAT_4000_d1dc != '\x19') {
    _DAT_4000_d1e6 = uRam0000044c >> 4;
  }
  piVar5 = (int *)&DAT_4000_d82c;
  iVar4 = _DAT_4000_d1e6 * 0x10;
  iVar2 = 0;
  iVar3 = 8;
  do {
    piVar1 = piVar5;
    piVar5 = piVar5 + 1;
    *piVar1 = iVar2;
    iVar2 = iVar2 + iVar4;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  return;
}
