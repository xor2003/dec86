
uint __cdecl16near FUN_1000_1788(uint param_1,int *param_2)

{
  int *piVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  int unaff_DI;

  piVar1 = param_2;
  bVar2 = *(byte *)(param_2 + 3);
  if (((bVar2 & 0x82) != 0) && ((bVar2 & 0x40) == 0)) {
    param_2[1] = 0;
    if ((bVar2 & 1) != 0) {
      if ((bVar2 & 0x10) == 0) goto LAB_1000_17ff;
      *param_2 = param_2[2];
      bVar2 = bVar2 & 0xfe;
    }
    *(byte *)(param_2 + 3) = bVar2 & 0xef | 2;
    uVar4 = (uint)*(byte *)((int)param_2 + 7);
    if (((bVar2 & 8) == 0) &&
       (((bVar2 & 4) != 0 ||
        (((*(byte *)(param_2 + 0x50) & 1) == 0 &&
         (((((param_2 == (int *)0x446 || (param_2 == (int *)0x44e)) || (param_2 == (int *)0x45e)) &&
           ((*(byte *)(uVar4 + 0x299) & 0x40) != 0)) ||
          (FUN_1000_1f8e(param_2), (*(byte *)(piVar1 + 3) & 8) == 0)))))))) {
      iVar3 = FUN_1000_204a(uVar4,&param_1,1);
      unaff_DI = 1;
    }
    else {
      iVar3 = *piVar1 - piVar1[2];
      *piVar1 = piVar1[2] + 1;
      piVar1[1] = piVar1[0x51] + -1;
      if (iVar3 == 0) {
        iVar3 = 0;
        unaff_DI = 0;
        if ((*(byte *)(uVar4 + 0x299) & 0x20) != 0) {
          FUN_1000_1fd0(uVar4,0,0,2);
          iVar3 = 0;
          unaff_DI = 0;
        }
      }
      else {
        iVar3 = FUN_1000_204a(uVar4,piVar1[2],iVar3,iVar3);
      }
      *(undefined1 *)piVar1[2] = (char)param_1;
    }
    if (iVar3 == unaff_DI) {
      return param_1 & 0xff;
    }
  }
LAB_1000_17ff:
  *(byte *)(piVar1 + 3) = *(byte *)(piVar1 + 3) | 0x20;
  return 0xffff;
}
