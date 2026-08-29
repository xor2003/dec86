
undefined4 FUN_1000_143a(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulong uVar1;
  long lVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  bool bVar11;
  char cVar12;
  uint uVar10;

  cVar12 = (int)param_2 < 0;
  if ((bool)cVar12) {
    bVar11 = param_1 != 0;
    param_1 = -param_1;
    param_2 = -(uint)bVar11 - param_2;
  }
  if ((int)param_4 < 0) {
    cVar12 = cVar12 + '\x01';
    bVar11 = param_3 != 0;
    param_3 = -param_3;
    param_4 = -(uint)bVar11 - param_4;
  }
  uVar4 = param_1;
  uVar7 = param_3;
  uVar3 = param_2;
  uVar10 = param_4;
  if (param_4 == 0) {
    uVar4 = param_2 / param_3;
    iVar5 = (int)(((ulong)param_2 % (ulong)param_3 << 0x10 | (ulong)param_1) / (ulong)param_3);
  }
  else {
    do {
      uVar8 = uVar3;
      uVar6 = uVar4;
      uVar9 = uVar10 >> 1;
      uVar7 = uVar7 >> 1 | (uint)((uVar10 & 1) != 0) << 0xf;
      uVar4 = uVar6 >> 1 | (uint)((uVar8 & 1) != 0) << 0xf;
      uVar3 = uVar8 >> 1;
      uVar10 = uVar9;
    } while (uVar9 != 0);
    uVar1 = (CONCAT22(uVar8,uVar6) >> 1) / (ulong)uVar7;
    iVar5 = (int)uVar1;
    lVar2 = (ulong)param_3 * (uVar1 & 0xffff);
    uVar4 = (uint)((ulong)lVar2 >> 0x10);
    uVar7 = uVar4 + iVar5 * param_4;
    if (((CARRY2(uVar4,iVar5 * param_4)) || (param_2 < uVar7)) ||
       ((param_2 <= uVar7 && (param_1 < (uint)lVar2)))) {
      iVar5 = iVar5 + -1;
    }
    uVar4 = 0;
  }
  if (cVar12 == '\x01') {
    bVar11 = iVar5 != 0;
    iVar5 = -iVar5;
    uVar4 = -(uint)bVar11 - uVar4;
  }
  return CONCAT22(uVar4,iVar5);
}
