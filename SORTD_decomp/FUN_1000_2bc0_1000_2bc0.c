
/* WARNING: Instruction at (ram,0x00012be2) overlaps instruction at (ram,0x00012be1)
    */

void __cdecl16far FUN_1000_2bc0(undefined2 param_1)

{
  byte bVar1;
  undefined1 uVar2;
  byte in_ZF;

  FUN_1000_2e1a();
  uVar2 = 0;
  if ((char)param_1 != '\0' || (char)((uint)param_1 >> 8) != '\0') {
    uVar2 = 0xff;
  }
  if ((in_ZF & 1) == 0) {
    DAT_4000_d23e = DAT_4000_d23e >> 1;
  }
  bVar1 = DAT_4000_d23e;
  DAT_4000_d23e = uVar2;
  FUN_1000_30f7(bVar1);
  FUN_1000_2e3b();
  return;
}
