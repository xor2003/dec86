
undefined2 __cdecl16near FUN_1000_2318(undefined1 *param_1)

{
  code *pcVar1;
  undefined1 in_CL;
  undefined1 in_CH;
  undefined1 extraout_DL;
  undefined1 extraout_DH;

  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  *param_1 = in_CH;
  param_1[1] = in_CL;
  param_1[2] = extraout_DH;
  param_1[3] = extraout_DL;
  return 0;
}
