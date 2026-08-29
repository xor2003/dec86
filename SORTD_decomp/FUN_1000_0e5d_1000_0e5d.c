
void FUN_1000_0e5d(int param_1,int param_2)

{
  int iVar1;
  undefined2 unaff_SI;

  FUN_1000_1222();
  if (param_1 != 0) {
    if (param_2 < 0x4b) {
      param_2 = 0x4b;
    }
    func_0x0001131e(0x43,0xb6);
    iVar1 = FUN_1000_143a(0x34dc,0x12,param_1,param_1 >> 0xf);
    param_1._0_1_ = (char)iVar1;
    func_0x0001131e(0x42,(int)(char)param_1);
    param_1._1_1_ = (char)((uint)iVar1 >> 8);
    func_0x0001131e(0x42,(int)param_1._1_1_);
    FUN_1000_1310();
    unaff_SI = 0xeed;
    func_0x0001131e(0x61);
    param_1 = iVar1;
  }
  FUN_1000_0f18(param_2,param_2 >> 0xf);
  if (param_1 != 0) {
    func_0x0001131e(0x61,unaff_SI);
  }
  return;
}
