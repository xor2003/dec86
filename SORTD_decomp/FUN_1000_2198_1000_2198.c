
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_2198(void)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  undefined4 uVar4;
  undefined2 uVar5;
  undefined2 uVar6;

  pcVar2 = (char *)FUN_1000_24c8(0x5c6);
  uVar4 = CONCAT22(_DAT_4000_d5c4,_DAT_4000_d5c2);
  if ((pcVar2 != (char *)0x0) && (uVar4 = CONCAT22(_DAT_4000_d5c4,_DAT_4000_d5c2), *pcVar2 != '\0'))
  {
    FUN_1000_249c(_DAT_4000_d5c8,pcVar2,3);
    uVar6 = 0;
    uVar5 = 0xe10;
    pcVar2 = pcVar2 + 3;
    uVar4 = thunk_FUN_1000_2686(pcVar2,0xe10,0);
    _DAT_4000_d5c2 = FUN_1000_1f38(uVar4,uVar5,uVar6);
    iVar3 = 0;
    while (pcVar2[iVar3] != '\0') {
      cVar1 = pcVar2[iVar3];
      if ((((*(byte *)(cVar1 + 0x33b) & 4) == 0) && (cVar1 != '-')) ||
         (iVar3 = iVar3 + 1, 2 < iVar3)) break;
    }
    if (pcVar2[iVar3] == '\0') {
      *_DAT_4000_d5ca = '\0';
    }
    else {
      FUN_1000_249c(_DAT_4000_d5ca,pcVar2 + iVar3,3);
    }
    _DAT_4000_d5c6 = (uint)(*_DAT_4000_d5ca != '\0');
    uVar4 = _DAT_4000_d5c2;
  }
  _DAT_4000_d5c4 = (undefined2)((ulong)uVar4 >> 0x10);
  _DAT_4000_d5c2 = (undefined2)uVar4;
  return;
}
