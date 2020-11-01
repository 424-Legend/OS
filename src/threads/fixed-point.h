#ifndef __THREAD_FIXED_POINT_H
#define __THREAD_FIXED_POINT_H

#define FP_SHIFT_AMOUNT 16
typedef int fixed_t;

#define CONVERT_N_TO_FIXED_POINT(n)             ((fixed_t)( n << FP_SHIFT_AMOUNT) )
#define CONVERT_X_TO_INTEGER_ZERO(x)            (x >> FP_SHIFT_AMOUNT )
#define CONVERT_X_TO_INTEGER_NEAREST(x)        (x >= 0 ? ((x + (1 << (FP_SHIFT_AMOUNT - 1))) >> FP_SHIFT_AMOUNT) \
                                                            : ((x - (1 << (FP_SHIFT_AMOUNT - 1))) >> FP_SHIFT_AMOUNT))

#define ADD_X_AND_Y(x,y)                   ( x + y ) 
#define SUB_Y_FROM_X(x,y)                  ( x - y )
#define ADD_X_AND_N(x,n)                   ( x + ( n << FP_SHIFT_AMOUNT ) )
#define SUB_N_FROM_X(x,n)                  (x - (n << FP_SHIFT_AMOUNT))
#define MULT_X_BY_Y(x,y)                    ((fixed_t)(((int64_t) x) * y >> FP_SHIFT_AMOUNT))  
#define MULT_X_BY_N(x,n)                    ( x * n )
#define DIV_X_BY_Y(x,y)                     ((fixed_t)((((int64_t) x) << FP_SHIFT_AMOUNT) / y))
#define DIV_X_BY_N(x,n)                      ( x / n )
#endif /* thread/fixed_point.h */
