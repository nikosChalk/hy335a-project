/**
 * Macro utils
 */

#ifndef MICROTCP_UTILS_H
#define MICROTCP_UTILS_H

#define MIN2(X,Y) (((X) < (Y)) ? (X) : (Y))
#define MIN3(X,Y,Z) (MIN2(X,Y) < (Z)) ? MIN2(X,Y) : ((Z))

#define MAX(X,Y) (((X) > (Y)) ? (X) : (Y))
#define ABS(X) ((X)<0 ? -(X) : X)

#endif //MICROTCP_UTILS_H
