
undefined4 __cdecl16near FUN_1000_3732(void)

{
  undefined1 uVar1;
  char in_CL;
  undefined2 in_DX;
  byte in_BH;

  uVar1 = (undefined1)((uint)in_DX >> 8);
  *(undefined2 *)((uint)in_BH * 2 + 0x450) = CONCAT11(uVar1,(char)in_DX + in_CL);
  return CONCAT22(CONCAT11(uVar1,(char)in_DX + in_CL),(uint)in_BH * 2);
}
