
undefined2 __cdecl16near FUN_1000_22fe(undefined1 *param_1)

{
  code *pcVar1;
  undefined1 uVar2;
  undefined2 in_CX;
  undefined1 extraout_DL;
  undefined1 extraout_DH;

  pcVar1 = (code *)swi(0x21);
  uVar2 = (*pcVar1)();
  *(undefined2 *)(param_1 + 2) = in_CX;
  param_1[1] = extraout_DH;
  *param_1 = extraout_DL;
  param_1[4] = uVar2;
  return 0;
}
