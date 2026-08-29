
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_34b8(void)

{
  undefined1 *puVar1;
  undefined1 *puVar2;
  undefined2 *puVar3;
  int in_CX;
  int iVar4;
  undefined1 *in_BX;
  undefined2 *puVar5;
  undefined1 *puVar6;

  if (in_CX == 0x27) {
    puVar5 = (undefined2 *)&DAT_4000_d20e;
    for (iVar4 = 0x17; iVar4 != 0; iVar4 = iVar4 + -1) {
      puVar3 = puVar5;
      puVar5 = puVar5 + 1;
      *puVar3 = 0x34b6;
    }
  }
  puVar6 = (undefined1 *)&DAT_4000_d1d8;
  for (; in_CX != 0; in_CX = in_CX + -1) {
    puVar2 = puVar6;
    puVar6 = puVar6 + 1;
    puVar1 = in_BX;
    in_BX = in_BX + 1;
    *puVar2 = *puVar1;
  }
  (*_DAT_4000_d21a)(0x4cff);
  DAT_4000_d76a = 0;
  return;
}
