#include <stdio.h>
#include <string.h>
#include <windows.h>



/**
 * @brief Extracts an ID from a given JSON string.
 *
 * @param[in] jsonString The JSON string containing the ID.
 * 
 * @return The extracted ID on success, or -1 if the ID could not be extracted.
 */
int ExtractIDFromJSON(IN char* jsonString) {
    
    int id = 0;

    if (sscanf(jsonString, "{\n\t\"id\": %d,", &id) == 1) {
        return id;
    } else {
        printf("Error: The ID could not be extracted from the JSON string.\n");
        return -1;
    }
}



/**
 * @brief Extracts the process status from a JSON string.
 *
 * @param[in]  jsonString The JSON string to parse.
 * @param[out] status     Buffer to store the extracted process status.
 * @param[in]  maxLen     Maximum length of the status buffer.
 * 
 * @return Returns 0 on success, or -1 if the process status could not be extracted.
 */
int ExtractProcessStatusFromJSON(IN char* jsonString, OUT char* status, IN size_t maxLen) {
    const char* statusKey = "\"process_status\": \"";
    const char* start = strstr(jsonString, statusKey);

    if (start) {
        start += strlen(statusKey); // Déplace le pointeur au début de la valeur
        const char* end = strchr(start, '\"');

        if (end && (end - start < maxLen)) {
            strncpy(status, start, end - start);
            status[end - start] = '\0'; // Assurez-vous que la chaîne est terminée correctement
            return 0; // Succès
        }
    }

    // Si process_status n'est pas trouvé ou si une autre erreur se produit
    strcpy(status, "Unknown");
    return -1; // Échec
}



/**
 * @brief      Determines if id present.
 *
 * @param[in]  id     The identifier
 * @param[in]  ids    The identifiers
 * @param[in]  count  The count
 *
 * @return     True if id present, False otherwise.
 */
BOOL isIDPresent(IN int id, IN int* ids, IN int count) {

    for (int i = 0; i < count; ++i) {
        if (ids[i] == id) {
            return TRUE; // The ID is already present
        }
    
    }

    return FALSE; // ID not present

}