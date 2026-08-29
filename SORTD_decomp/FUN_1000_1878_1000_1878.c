
undefined2 __cdecl16near FUN_1000_1878(undefined2 param_1,char *param_2)

{
  byte bVar1;
  undefined2 uVar2;

  FUN_1000_1222();
  if (*param_2 == '\0') {
    return 0;
  }
  bVar1 = *param_2 - 0x20;
  if (bVar1 < 0x59) {
    bVar1 = *(byte *)(ulong)(bVar1 + 0x2d8) & 0xf;
  }
  else {
    bVar1 = 0;
  }
                    /* WARNING: Could not emulate address calculation at 0x000118bc */
                    /* WARNING: Treating indirect jump as call */
  uVar2 = (*(code *)*(undefined2 *)
                     ((char)(*(byte *)(ulong)((byte)(bVar1 * '\b') + 0x2d8) >> 4) * 2 + 0x1868))();
  return uVar2;
}
