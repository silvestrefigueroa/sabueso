#include <stdlib.h>
#include <stdio.h>
#include <string.h>
char **splitter ( char *string, const char sep) {

    char       **lista;
    char       *p = string;
    int         i = 0;

    int         pos;
    const int   len = strlen (string);

    lista = (char **) malloc (sizeof (char *));
    if (lista == NULL) {                      /* Cannot allocate memory */
        return NULL;
    }

    lista[pos=0] = NULL;

    while (i <len) {

        while ((p[i] == sep) && (i <len))
            i++;

        if (i <len) {

            char **tmp = (char **) realloc (lista , (pos + 2) * sizeof (char *));
            if (tmp == NULL) {       /* Cannot allocate memory */
                free (lista);
                return NULL;
            }
            lista = tmp;
            tmp = NULL;

            lista[pos + 1] = NULL;
            lista[pos] = (char *) malloc (sizeof (char));
            if (lista[pos] == NULL) {         /* Cannot allocate memory */
                for (i = 0; i <pos; i++)
                    free (lista[i]);
                free (lista);
                return NULL;
            }

            int j = 0;
            for (i=i; ((p[i] != sep) && (i <len)); i++) {
                lista[pos][j] = p[i];
                j++;

                char *tmp2 = (char *) realloc (lista[pos],(j + 1) * sizeof (char));
                if (lista[pos] == NULL) {     /* Cannot allocate memory */
                    for (i = 0; i <pos; i++)
                        free (lista[i]);
                    free (lista);
                    return NULL;
                }
                lista[pos] = tmp2;
                tmp2 = NULL;
            }
            lista[pos][j] = '\0';
            pos++;
        }
    }

    return lista;
}



/*

//+----------------------------------------------------------------------------+
//| main
//+----------------------------------------------------------------------------+
int main ( int argc , char *argv[]) {

    char    **listSplit;
    short   i;

    if (argc==2) {
        printf ("Parse '%s'\n",argv[1]);

        listSplit = splitter(argv[1],'|');

        i=0;
        while (listSplit[i]!=NULL) {
            printf("-> %s\n" , listSplit[i++]);
        }
    }

    return 0;
}

*/
