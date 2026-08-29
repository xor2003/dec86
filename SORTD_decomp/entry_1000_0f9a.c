
/* WARNING: Stack frame is not setup normally: Input value of stackpointer is not used */
/* WARNING: This function may have set the stack pointer */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16far entry(void)

{
  undefined1 *puVar1;
  code *pcVar2;
  code *pcVar3;
  byte bVar4;
  int iVar5;
  undefined1 *puVar6;
  undefined1 *puVar7;
  undefined1 *puVar8;
  undefined1 *puVar9;
  undefined2 *puVar10;
  undefined1 *puVar11;
  uint uVar12;
  undefined1 *puVar13;
  undefined2 unaff_ES;
  undefined2 uVar14;

  uVar14 = 0x4cff;
  puVar6 = (undefined1 *)0x800;
  pcVar3 = (code *)swi(0x21);
  bVar4 = (*pcVar3)();
  if (bVar4 < 2) {
    *(undefined2 *)(puVar6 + -2) = unaff_ES;
    *(undefined2 *)(puVar6 + -4) = 0;
    return;
  }
  uVar12 = _DAT_4000_cff2 + 0xea26;
  if (0xfff < uVar12) {
    uVar12 = 0x1000;
  }
  puVar7 = puVar6 + 0xbae;
  puVar13 = puVar6 + 0xbae;
  if ((undefined1 *)0xf451 < puVar6) {
    *(undefined2 *)(puVar6 + 0xbac) = 0x15da;
    uVar14 = *(undefined2 *)(puVar6 + 0xbac);
    *(undefined2 *)(puVar6 + 0xbac) = 0xfc8;
    FUN_1000_14d4();
    *(undefined2 *)(puVar6 + 0xbac) = 0;
    *(undefined2 *)(puVar6 + 0xbaa) = 0xfce;
    FUN_1000_1753();
    pcVar3 = (code *)swi(0x21);
    (*pcVar3)();
    puVar13 = puVar7;
  }
  DAT_15da_0254 = uVar12 * 0x10 + -1;
  DAT_15da_0256 = 0x15da;
  puVar8 = (undefined1 *)((uint)puVar13 & 0xfffe);
  DAT_15da_0260 = puVar8 + -2;
  DAT_15da_025a = puVar8;
  *(undefined2 *)(puVar8 + -2) = 0xfffe;
  puVar9 = puVar8 + -4;
  DAT_15da_025c = puVar8 + -4;
  DAT_15da_025e = puVar8 + -4;
  DAT_15da_0250 = puVar8 + -4;
  *(undefined2 *)(puVar8 + -4) = 1;
  *(int *)&DAT_4000_cff2 = uVar12 + 0x15da;
  pcVar3 = (code *)swi(0x21);
  (*pcVar3)();
  DAT_15da_0290 = uVar14;
  *(undefined2 *)(puVar9 + -2) = 0x15da;
  uVar14 = *(undefined2 *)(puVar9 + -2);
  puVar13 = (undefined1 *)&DAT_4000_d734;
  for (iVar5 = 0x46c; iVar5 != 0; iVar5 = iVar5 + -1) {
    puVar1 = puVar13;
    puVar13 = puVar13 + 1;
    *puVar1 = 0;
  }
  *(undefined2 *)(puVar9 + -2) = 0x15da;
  pcVar2 = (code *)*(int *)0x646;
  if (pcVar2 != (code *)0x0) {
    puVar10 = (undefined2 *)(puVar9 + -2);
    puVar9 = puVar9 + -2;
    *puVar10 = 0x1031;
    (*pcVar2)();
  }
  *(undefined2 *)(puVar9 + -2) = 0x1034;
  FUN_1000_16aa();
  puVar11 = puVar9 + -2;
  *(undefined2 *)(puVar9 + -2) = 0x1037;
  FUN_1000_151c();
  *(undefined2 *)(puVar11 + -2) = 0x103c;
  FUN_1000_1084();
  *(undefined2 *)(puVar11 + -2) = 0x15da;
  uVar14 = *(undefined2 *)(puVar11 + -2);
  *(undefined2 *)(puVar11 + -2) = *(undefined2 *)&DAT_4000_d2a1;
  *(undefined2 *)(puVar11 + -4) = *(undefined2 *)0x2af;
  *(undefined2 *)(puVar11 + -6) = *(undefined2 *)0x2ad;
  *(undefined2 *)(puVar11 + -8) = 0x104d;
  uVar14 = FUN_1000_0010();
  *(undefined2 *)(puVar11 + -8) = uVar14;
  *(undefined2 *)(puVar11 + -10) = 0x1051;
  FUN_1000_1152();
  return;
}
