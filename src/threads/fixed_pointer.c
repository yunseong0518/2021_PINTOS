#include "fixed_pointer.h"

int
fp_convert_nfp(int n) 
{
    return n*F;
}

int
fp_convert_x_int_zero(int x)
{
    return x/F;
}

int
fp_convert_x_int_near(int x)
{
    if (x >= 0) return (x + F / 2) / F;
    else return (x - F / 2) / F;
}

int
fp_add_xy(int x, int y)
{
    return x + y;
}

int
fp_sub_xy(int x, int y)
{
    return x - y;
}

int
fp_add_xn(int x, int n)
{
    return x + n*F;
}

int
fp_sub_xn(int x, int n)
{
    return x - n*F;
}

int
fp_mul_xy(int x, int y)
{
    return ((int64_t)x)*y/F;
}

int
fp_mul_xn(int x, int n)
{
    return x*n;
}

int
fp_div_xy(int x, int y)
{
    return ((int64_t)x*F)/y;
}

int
fp_div_xn(int x, int n)
{
    return x/n;
}