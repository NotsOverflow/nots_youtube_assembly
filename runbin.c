//runbin_p.c
 
// plein de librairy trés utiles
#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <stdlib.h>
#include <malloc.h>
#include <fcntl.h>
#include <intrin.h>
 
// pour que les pointeurs vers functions deviennes plus simple a écrire

typedef void (*FUNCPTR)(); 
 
int main(int argc, char **argv)
{
    FUNCPTR func; // un pointeur vers founction
    void *buf; // un pointeur vers rien, juste une adresse en some
    int fd, len; // deux int, un descripteur de fichier et un qui représente une longueur
    int debug; // un int ( je croi un bollein , mais ça éxiste pas en C , on utilise des int)
    char *filename; // un pointeur vers un charactère ( surement vers le premier du début d'une chaine )
    DWORD oldProtect; // un Dword qui s'apelle oldProtect ( surement un typedef qui est dans les includes d'en haut et qui sert en legacy)
 
    /* 
     on test si il y a 3 argument
     et si la longueur du premier ne fait que deux charactère
     et si la valeur de celui-ci est égale a '-d'
     sinon on test si il y a selement 2 argument
     sinon on dit que tu sais pas utiliser le prog et on te rapelle comment on fait
    */ 
    if (argc == 3 && strlen(argv[1]) == 2 && strncmp(argv[1], "-d", 2) == 0) {
        debug = 1; // debug activer
        filename = argv[2]; // le nom du fichier et donc le troisième argument
    } else if (argc == 2) {
        debug = 0; // debug désactiver
        filename = argv[1]; // le nom du ficher et le second argument
    } else {
        fprintf(stderr, "usage: runbin [-d] <filename>\n"); // aprend a utiliser ce programme boulet
        fprintf(stderr, "  -d    insert debugger breakpoint\n"); // ya même des options ^^
        return 1; // on quite en indiquant une érreur
    }
    // on ouvre le fichier en lecture seul et en binaire et on le place son file descriptor dans fd
    fd = _open(filename, _O_RDONLY | _O_BINARY); 
 
    // si le file descriptor vaut -1 c'est que ça a pas marcher :p
    if (-1 == fd) {
        perror("Error opening file");
        return 1;
    }
 
    // on place la taille du fichier dans len
    len = _filelength(fd);
 
    // si sa taille est négative alors c'est pas normal
    if (-1 == len) {
        perror("Error getting file size");
        return 1;
    }
    
    // on demande un éspace pour stoquer le fichier en mémoire de taille len
    buf = malloc(len);
 
    // si regarde si on nous a bien résérver une place pour le fichier
    if (NULL == buf) {
        perror("Error allocating memory");
        return 1;
    }
 
    // la mémoire allouer est protéger en éxécution il faut demander l'autorisation
    if (0 == VirtualProtect(buf, len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        fprintf(stderr, "Error setting memory executable: error code %d\n", GetLastError());
        return 1;
    }        
 
    // on copie le fichier dans l'éspace fraichement allouer
    if (len != _read(fd, buf, len)) {
        perror("error reading from file");
        return 1;
    }
 
    // on met l'adresse de cette éspace dans function
    func = (FUNCPTR)buf;
 
    // si on a demander un débug, c'est le moment de stoper l'éxécution car tout le réste est le shellcode
    if (debug) {
        __debugbreak();
    }
 
    // on execute le shellcode 
    func();
 
    return 0; // on quite sans erreur
}
