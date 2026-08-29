
undefined2 __cdecl16near FUN_1000_2234(int param_1)

{
  undefined2 uVar1;
  int iVar2;
  uint uVar3;
  int local_6;

  if ((*(int *)(param_1 + 8) < 3) || (9 < *(int *)(param_1 + 8))) goto LAB_1000_22f5;
  if ((*(int *)(param_1 + 8) < 4) || (8 < *(int *)(param_1 + 8))) {
    uVar3 = *(int *)(param_1 + 10) + 0x76c;
    if (((int)uVar3 < 0x7c3) || (*(int *)(param_1 + 8) != 3)) {
      local_6 = *(int *)(*(int *)(param_1 + 8) * 2 + 0x5ae);
    }
    else {
      local_6 = *(int *)(*(int *)(param_1 + 8) * 2 + 0x5ac) + 7;
    }
    if ((uVar3 & 3) == 0) {
      local_6 = local_6 + 1;
    }
    local_6 = ((*(int *)(param_1 + 10) + -0x45) / 4 + (*(int *)(param_1 + 10) + -0x46) * 0x16d +
               local_6 + 4) % 7 - local_6;
    iVar2 = -local_6;
    if (*(int *)(param_1 + 8) == 3) {
      if ((iVar2 < *(int *)(param_1 + 0xe)) ||
         ((-*(int *)(param_1 + 0xe) == local_6 && (1 < *(int *)(param_1 + 4))))) goto LAB_1000_22e1;
    }
    else if ((*(int *)(param_1 + 0xe) < iVar2) ||
            ((*(int *)(param_1 + 0xe) == iVar2 && (*(int *)(param_1 + 4) < 1)))) goto LAB_1000_22e1;
LAB_1000_22f5:
    uVar1 = 0;
  }
  else {
LAB_1000_22e1:
    uVar1 = 1;
  }
  return uVar1;
}
