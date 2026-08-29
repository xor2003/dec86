
undefined4 __cdecl16near thunk_FUN_1000_2686(byte *param_1)

{
  byte *pbVar1;
  byte bVar2;
  uint uVar3;
  byte bVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  bool bVar11;

  iVar6 = 0;
  iVar8 = 0;
  do {
    do {
      pbVar1 = param_1;
      param_1 = param_1 + 1;
      bVar2 = *pbVar1;
      uVar5 = (uint)bVar2;
    } while (bVar2 == 0x20);
  } while (bVar2 == 9);
  if ((bVar2 != 0x2d) && (bVar2 != 0x2b)) goto LAB_1000_26a6;
  while( true ) {
    pbVar1 = param_1;
    param_1 = param_1 + 1;
    uVar5 = CONCAT11((char)(uVar5 >> 8),*pbVar1);
LAB_1000_26a6:
    bVar4 = (byte)uVar5;
    if ((0x39 < bVar4) || (uVar5 = uVar5 + 0xd0, bVar4 < 0x30)) break;
    uVar9 = iVar8 * 2;
    uVar7 = iVar6 << 1 | (uint)(iVar8 < 0);
    iVar6 = iVar8 << 2;
    uVar10 = iVar8 * 8;
    uVar3 = iVar8 * 10;
    iVar8 = uVar3 + uVar5;
    iVar6 = ((uVar7 << 1 | (uint)((int)uVar9 < 0)) << 1 | (uint)(iVar6 < 0)) + uVar7 +
            (uint)CARRY2(uVar10,uVar9) + (uint)CARRY2(uVar3,uVar5);
  }
  if (bVar2 == 0x2d) {
    bVar11 = iVar8 != 0;
    iVar8 = -iVar8;
    iVar6 = -(iVar6 + (uint)bVar11);
  }
  return CONCAT22(iVar6,iVar8);
}
