
/* WARNING (jumptable): Unable to track spacebase fully for stack */
/* WARNING: Unable to track spacebase fully for stack */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_1000_151c(undefined2 param_1,undefined2 param_2)

{
  char *pcVar1;
  char cVar2;
  char *pcVar3;
  undefined2 uVar4;
  code *pcVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  undefined2 *puVar9;
  char *pcVar10;
  char *pcVar11;
  int iVar12;
  char *pcVar13;
  undefined2 uVar14;
  undefined2 unaff_SS;
  undefined2 in_stack_00000000;

  pcVar5 = (code *)swi(0x21);
  _DAT_4000_d2c6 = in_stack_00000000;
  _DAT_4000_d282 = (*pcVar5)();
  uVar8 = 1;
  if ((char)_DAT_4000_d282 != '\x02') {
    _DAT_4000_d2a5 = *(undefined2 *)0x2c;
    iVar6 = -0x8000;
    pcVar11 = (char *)0x0;
LAB_1000_1543:
    do {
      _DAT_4000_d2a3 = pcVar11;
      if (iVar6 != 0) {
        iVar6 = iVar6 + -1;
        pcVar3 = pcVar11;
        pcVar11 = pcVar11 + 1;
        _DAT_4000_d2a3 = pcVar11;
        if (*pcVar3 != '\0') goto LAB_1000_1543;
      }
      pcVar11 = _DAT_4000_d2a3 + 1;
    } while (*_DAT_4000_d2a3 != '\0');
    _DAT_4000_d2a3 = _DAT_4000_d2a3 + 3;
    uVar8 = 0xffff;
    pcVar11 = _DAT_4000_d2a3;
    do {
      if (uVar8 == 0) break;
      uVar8 = uVar8 - 1;
      pcVar3 = pcVar11;
      pcVar11 = pcVar11 + 1;
    } while (*pcVar3 != '\0');
    uVar8 = ~uVar8;
  }
  iVar6 = 1;
  pcVar11 = (char *)0x81;
LAB_1000_1561:
  do {
    do {
      pcVar3 = pcVar11;
      pcVar11 = pcVar11 + 1;
      cVar2 = *pcVar3;
    } while (cVar2 == ' ');
  } while (cVar2 == '\t');
  if ((cVar2 != '\r') && (cVar2 != '\0')) {
    iVar6 = iVar6 + 1;
    do {
      pcVar11 = pcVar11 + -1;
LAB_1000_1574:
      pcVar3 = pcVar11;
      pcVar11 = pcVar11 + 1;
      cVar2 = *pcVar3;
      if ((cVar2 == ' ') || (cVar2 == '\t')) goto LAB_1000_1561;
      if ((cVar2 == '\r') || (cVar2 == '\0')) break;
      if (cVar2 == '\"') {
LAB_1000_15ad:
        do {
          while( true ) {
            while( true ) {
              pcVar3 = pcVar11;
              pcVar11 = pcVar11 + 1;
              cVar2 = *pcVar3;
              if ((cVar2 == '\r') || (cVar2 == '\0')) goto LAB_1000_15dd;
              if (cVar2 == '\"') goto LAB_1000_1574;
              if (cVar2 == '\\') break;
              uVar8 = uVar8 + 1;
            }
            uVar7 = 0;
            do {
              pcVar13 = pcVar11;
              uVar7 = uVar7 + 1;
              pcVar11 = pcVar13 + 1;
            } while (*pcVar13 == '\\');
            if (*pcVar13 == '\"') break;
            uVar8 = uVar8 + uVar7;
            pcVar11 = pcVar13;
          }
          uVar8 = uVar8 + (uVar7 >> 1) + (uint)((uVar7 & 1) != 0);
        } while ((uVar7 & 1) != 0);
        goto LAB_1000_1574;
      }
      if (cVar2 != '\\') {
        uVar8 = uVar8 + 1;
        goto LAB_1000_1574;
      }
      uVar7 = 0;
      do {
        uVar7 = uVar7 + 1;
        pcVar3 = pcVar11;
        pcVar11 = pcVar11 + 1;
      } while (*pcVar3 == '\\');
      if (*pcVar3 == '\"') {
        uVar8 = uVar8 + (uVar7 >> 1) + (uint)((uVar7 & 1) != 0);
        if ((uVar7 & 1) == 0) goto LAB_1000_15ad;
        goto LAB_1000_1574;
      }
      uVar8 = uVar8 + uVar7;
    } while( true );
  }
LAB_1000_15dd:
  *(int *)0x2ad = iVar6;
  iVar12 = (iVar6 + 1) * 2;
  iVar6 = -(uVar8 + iVar6 + iVar12 + 1 & 0xfffe);
  *(undefined1 **)0x2af = &stack0x0006 + iVar6;
  pcVar13 = &stack0x0006 + iVar12 + iVar6;
  *(undefined2 *)((int)&stack0x0004 + iVar6) = unaff_SS;
  uVar14 = *(undefined2 *)((int)&stack0x0004 + iVar6);
  *(char **)(&stack0x0006 + iVar6) = pcVar13;
  puVar9 = (undefined2 *)(&stack0x0008 + iVar6);
  pcVar3 = (char *)*(undefined4 *)&DAT_4000_d2a3;
  pcVar11 = (char *)pcVar3;
  do {
    pcVar1 = pcVar11;
    pcVar11 = pcVar11 + 1;
    cVar2 = *pcVar1;
    pcVar1 = pcVar13;
    pcVar13 = pcVar13 + 1;
    *pcVar1 = cVar2;
  } while (cVar2 != '\0');
  uVar4 = *(undefined2 *)&DAT_4000_d280;
  pcVar11 = (char *)0x81;
LAB_1000_1617:
  do {
    do {
      pcVar3 = pcVar11;
      pcVar11 = pcVar11 + 1;
      cVar2 = *pcVar3;
    } while (cVar2 == ' ');
  } while (cVar2 == '\t');
  if ((cVar2 == '\r') || (cVar2 == '\0')) {
LAB_1000_16a0:
    *(undefined2 *)((int)&stack0x0004 + iVar6) = unaff_SS;
    uVar14 = *(undefined2 *)((int)&stack0x0004 + iVar6);
    *puVar9 = 0;
                    /* WARNING: Could not recover jumptable at 0x000116a6. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*(code *)*(undefined2 *)&DAT_4000_d2c6)();
    return;
  }
  *puVar9 = pcVar13;
  puVar9 = puVar9 + 1;
  do {
    pcVar11 = pcVar11 + -1;
LAB_1000_162e:
    pcVar3 = pcVar11;
    pcVar11 = pcVar11 + 1;
    cVar2 = *pcVar3;
    if ((cVar2 == ' ') || (cVar2 == '\t')) {
      pcVar3 = pcVar13;
      pcVar13 = pcVar13 + 1;
      *pcVar3 = '\0';
      goto LAB_1000_1617;
    }
    if ((cVar2 == '\r') || (cVar2 == '\0')) {
LAB_1000_169d:
      *pcVar13 = '\0';
      goto LAB_1000_16a0;
    }
    pcVar10 = pcVar11;
    if (cVar2 == '\"') {
LAB_1000_166a:
      while( true ) {
        pcVar11 = pcVar10 + 1;
        cVar2 = *pcVar10;
        if ((cVar2 == '\r') || (cVar2 == '\0')) goto LAB_1000_169d;
        if (cVar2 == '\"') break;
        if (cVar2 == '\\') {
          uVar8 = 0;
          do {
            pcVar10 = pcVar11;
            uVar8 = uVar8 + 1;
            pcVar11 = pcVar10 + 1;
          } while (*pcVar10 == '\\');
          if (*pcVar10 == '\"') {
            for (uVar7 = uVar8 >> 1; uVar7 != 0; uVar7 = uVar7 - 1) {
              pcVar3 = pcVar13;
              pcVar13 = pcVar13 + 1;
              *pcVar3 = '\\';
            }
            if ((uVar8 & 1) == 0) break;
            pcVar3 = pcVar13;
            pcVar13 = pcVar13 + 1;
            *pcVar3 = '\"';
            pcVar10 = pcVar11;
          }
          else {
            for (; uVar8 != 0; uVar8 = uVar8 - 1) {
              pcVar3 = pcVar13;
              pcVar13 = pcVar13 + 1;
              *pcVar3 = '\\';
            }
          }
        }
        else {
          pcVar3 = pcVar13;
          pcVar13 = pcVar13 + 1;
          *pcVar3 = cVar2;
          pcVar10 = pcVar11;
        }
      }
      goto LAB_1000_162e;
    }
    if (cVar2 != '\\') {
      pcVar3 = pcVar13;
      pcVar13 = pcVar13 + 1;
      *pcVar3 = cVar2;
      goto LAB_1000_162e;
    }
    uVar8 = 0;
    do {
      uVar8 = uVar8 + 1;
      pcVar3 = pcVar11;
      pcVar11 = pcVar11 + 1;
    } while (*pcVar3 == '\\');
    if (*pcVar3 == '\"') {
      for (uVar7 = uVar8 >> 1; uVar7 != 0; uVar7 = uVar7 - 1) {
        pcVar3 = pcVar13;
        pcVar13 = pcVar13 + 1;
        *pcVar3 = '\\';
      }
      pcVar10 = pcVar11;
      if ((uVar8 & 1) == 0) goto LAB_1000_166a;
      pcVar3 = pcVar13;
      pcVar13 = pcVar13 + 1;
      *pcVar3 = '\"';
      goto LAB_1000_162e;
    }
    for (; uVar8 != 0; uVar8 = uVar8 - 1) {
      pcVar3 = pcVar13;
      pcVar13 = pcVar13 + 1;
      *pcVar3 = '\\';
    }
  } while( true );
}
