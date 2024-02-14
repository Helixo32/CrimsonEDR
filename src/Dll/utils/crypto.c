#include <stdint.h>
#include <string.h>

#include "structure.h"



/**
 * @brief Calculates a hash value for a given string.
 *
 * Uses the djb2 algorithm by Dan Bernstein to compute a hash value for a string.
 * This algorithm has been widely used because of its simplicity and effectiveness in distributing hash values.
 *
 * @param[in]  str The null-terminated string to hash.
 * 
 * @return The computed hash value as an unsigned long.
 */
unsigned long hashString(const char* str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; // hash * 33 + c

    return hash;
}



/**
 * @brief Generates a unique ID based on various fields of an INFORMATION_DETECTION structure.
 *
 * This function computes a hash value by combining the hash results of multiple string fields 
 * within an INFORMATION_DETECTION structure and the process ID. It uses an XOR operation to 
 * combine these hash values into a single unique identifier. This approach helps in generating 
 * a distinct ID for each detection based on its attributes.
 *
 * @param[in]  pInformationDetection  Pointer to the INFORMATION_DETECTION structure containing the detection details.
 * 
 * @return A unique unsigned long hash value representing the identification of the detection information.
 */
unsigned long GenerateIdFromInformation(PINFORMATION_DETECTION pInformationDetection) {
    unsigned long hashValue = 0;

    // Hash chaque champ en utilisant hashString et combine les résultats
    hashValue ^= hashString(pInformationDetection->image_name);
    hashValue ^= hashString(pInformationDetection->image_path);
    hashValue ^= hashString(pInformationDetection->description);
    hashValue ^= hashString(pInformationDetection->category);
    hashValue ^= hashString(pInformationDetection->detection_type);
    hashValue ^= (unsigned long)pInformationDetection->pid; // Directement intégrer le PID dans le hash
    hashValue ^= hashString(pInformationDetection->process_status);
    hashValue ^= hashString(pInformationDetection->information);

    return hashValue;
}
