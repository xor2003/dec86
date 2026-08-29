
void __cdecl16near FUN_1000_3400(void)

{
  byte bVar1;
  long lVar2;
  undefined2 uVar3;
  undefined2 unaff_SS;

  bVar1 = *(byte *)0x1e7;
  lVar2 = (ulong)bVar1 * (ulong)(uint)(*(int *)&DAT_4000_d1e6 << 4);
  uVar3 = (undefined2)((ulong)lVar2 >> 0x10);
  *(undefined2 *)0x44e = (int)lVar2;
  *(byte *)0x462 = bVar1;
  return;
}
