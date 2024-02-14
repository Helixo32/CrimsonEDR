#include <stdio.h>
#include <string.h>
#include <windows.h>



/**
 * @brief Checks if two byte arrays are equal.
 *
 * Compares each element of two byte arrays to determine if they are identical.
 *
 * @param[in]  array1 The first byte array.
 * @param[in]  array2 The second byte array.
 * @param[in]  length The number of elements in each array to compare.
 * 
 * @return Returns TRUE if all elements are equal, otherwise FALSE.
 */
BOOL areArraysEqual(IN BYTE array1[], IN BYTE array2[], IN size_t length) {

    for (size_t i = 0; i < length; i++) {
        if (array1[i] != array2[i]) {
            return FALSE;
        }
    }

    return TRUE;

}