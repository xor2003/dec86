
void __cdecl16near FUN_1000_27d8(void)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  uint in_CX;
  undefined2 in_DX;
  undefined2 extraout_DX;
  undefined2 in_BX;
  undefined2 unaff_SS;

  if ((in_CX != 0) && (*(char *)&DAT_4000_d7a7 == '\0')) {
    do {
      uVar2 = (int)(char)in_DX + in_CX;
      iVar3 = uVar2 - *(uint *)&DAT_4000_d7a5;
      if (uVar2 < *(uint *)&DAT_4000_d7a5 || iVar3 == 0) {
        FUN_1000_36da();
        return;
      }
      uVar2 = iVar3 - 1;
      if (uVar2 < in_CX) {
        FUN_1000_36da(uVar2,in_BX);
      }
      if (*(char *)&DAT_4000_d7a8 == '\0') {
        *(undefined1 *)&DAT_4000_d7a7 = 1;
        pcVar1 = (code *)swi(0x10);
        (*pcVar1)();
        return;
      }
      in_CX = uVar2;
      FUN_1000_2825();
      in_DX = extraout_DX;
    } while (in_CX != 0);
  }
  return;
}
