
void __cdecl16near FUN_1000_132c(void)

{
  code *pcVar1;
  undefined2 *puVar2;
  uint in_CX;
  uint uVar3;
  uint uVar4;
  uint extraout_DX;
  byte extraout_DH;
  uint extraout_DX_00;
  uint uVar5;
  uint uVar6;
  undefined4 uVar7;

  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  uVar3 = in_CX;
  uVar6 = extraout_DX;
  (*pcVar1)();
  puVar2 = (undefined2 *)(uint)extraout_DH;
  pcVar1 = (code *)swi(0x21);
  uVar4 = uVar3;
  (*pcVar1)(uVar3 >> 8);
  uVar5 = extraout_DX_00;
  if ((uVar6 != extraout_DX_00) && (uVar5 = extraout_DX_00, (char)uVar3 == '\x17')) {
    uVar4 = in_CX;
    uVar5 = uVar6;
  }
  uVar7 = FUN_1000_1e42(uVar4 - 0x7bc,uVar5 >> 8);
  if (puVar2 != (undefined2 *)0x0) {
    puVar2[1] = (int)((ulong)uVar7 >> 0x10);
    *puVar2 = (int)uVar7;
  }
  return;
}
