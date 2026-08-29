
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined2 * __cdecl16far FUN_1000_2ac8(undefined2 *param_1)

{
  undefined1 uVar1;
  int iVar2;
  undefined2 uVar3;
  undefined2 *puVar4;
  undefined2 uVar5;
  bool bVar6;
  undefined4 uVar7;

  uVar5 = (undefined2)((ulong)param_1 >> 0x10);
  puVar4 = (undefined2 *)param_1;
  bVar6 = true;
  uVar3 = 0;
  iVar2 = 0x20;
  DAT_4000_d736 = 0;
  uVar7 = FUN_1000_33fa();
  if (!bVar6) {
    uVar7 = CONCAT22((uint)DAT_4000_d1ff * (uint)DAT_4000_d200,_DAT_4000_d1dd);
    iVar2 = CONCAT11((char)((uint)iVar2 >> 8),DAT_4000_d1e3) + 1;
    uVar3 = _DAT_4000_d1df;
  }
  *param_1 = (int)uVar7;
  puVar4[1] = uVar3;
  puVar4[2] = (uint)DAT_4000_d1db;
  puVar4[3] = (uint)DAT_4000_d1dc;
  puVar4[4] = iVar2;
  puVar4[5] = (int)((ulong)uVar7 >> 0x10);
  iVar2 = CONCAT11((char)((ulong)uVar7 >> 0x18),DAT_4000_d1e8) + 1;
  puVar4[6] = iVar2;
  uVar1 = (undefined1)((uint)iVar2 >> 8);
  puVar4[7] = CONCAT11(uVar1,DAT_4000_d1d9);
  puVar4[8] = CONCAT11(uVar1,DAT_4000_d745);
  puVar4[9] = CONCAT11(uVar1,DAT_4000_d746);
  puVar4[10] = _DAT_4000_d747;
  return puVar4;
}
