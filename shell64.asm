;------------------------------------------------------------------------------|\
;                                                              _____           |\
;      Autor: Notsgnik                                       /||   /           |\
;      Email: Labruillere gmail.com                         / ||  /            |\
;      website: notsgnik.github.io                         /  || /             |\
;      License: GPL v3                                    /___||/              |\
;                                                                              |\
;------------------------------------------------------------------------------|
; ml64 shell64.asm /link /entry:main

; provenan de http://mcdermottcybersecurity.com/articles/windows-x64-shellcode
; sous licence MIT (http://www.opensource.org/licenses/mit-license.php)

;shell64.asm

 .code
 
;note: ExitProcess est suivie ( voir lookup_api ) 

main proc
    sub rsp, 28h            		; reserve la stack pour les function appeler
    and rsp, 0fffffffffffffff0h     ; on aligne sur 16 byte   
 
    lea rdx, loadlib_func
    lea rcx, kernel32_dll
    call lookup_api         		; on cherche l'adresse de LoadLibraryA
    mov r15, rax            		; on la met de cote
 
    lea rcx, user32_dll
    call rax                		; on charge user32.dll
 
    lea rdx, msgbox_func
    lea rcx, user32_dll
    call lookup_api         		; on choppe l'adresse de MessageBoxA
 
    xor r9, r9              		; type MB_OK
    lea r8, title_str       		; titre de la box
    lea rdx, hello_str      		; message de la box
    xor rcx, rcx            		; pas de hundle
    call rax                		; c'est partie!
 
    lea rdx, exitproc_func
    lea rcx, kernel32_dll
    call lookup_api         		; on chope l'adresse de ExitProcess
 
    xor rcx, rcx            		; valeur du sortie ( 0 tout est OK! )
    call rax                		; c'est partie!
 
main endp
 
kernel32_dll    db  'KERNEL32.DLL', 0
loadlib_func    db  'LoadLibraryA', 0
user32_dll      db  'USER32.DLL', 0
msgbox_func     db  'MessageBoxA', 0
hello_str       db  'Hello world', 0
title_str       db  'Message', 0
exitproc_func   db  'ExitProcess', 0
 
;Cherche l'adresse d'une fonction en ce basan sur la table d'export des DLL
;rcx= Nom de la DLL, rdx= Nom de la function
;le nom de la DLL doit etre en majuscule
;r15= Addresse de LoadLibraryA (optionel, selement si la function est suivie )
;retourne l'address dans rax
;retourne 0 si la DLL n'est pas charger ou si la function n'est pas exporter


lookup_api  proc
    sub rsp, 28h            ; Prepare la stack si on apelle loadlibrary
 
start:
    mov r8, gs:[60h]        ; Le peb
    mov r8, [r8+18h]        ; La data du peb
    lea r12, [r8+10h]       ; InLoadOrderModuleList ( debut de la liste ) - a garder pour plus tard
    mov r8, [r12]           ; suit _LIST_ENTRY->Flink jusqu'au premier element de la liste
    cld
 
for_each_dll:               ; r8 pointe vers le _ldr_data_table_entry courent
 
    mov rdi, [r8+60h]       ; la chaine UNICODE_STRING est a 58h de distance dans la struct , la chaine chaine qui nous interesse a 60h
    mov rsi, rcx            ; le pointeur vers la dll que l'on cherche
 
compare_dll:
    lodsb                   ; charge les charactere du nom de la DLL
    test al, al             ; regarde si la string est fini 
    jz found_dll            ; si a la fin de la chaine tout les characteres corresponde on l'a trouver!
 
    mov ah, [rdi]           ; chope le charactere de la DLL courente
    cmp ah, 61h             ; 'a' minuscule
    jl uppercase
    sub ah, 20h             ; devien majuscule
 
uppercase:
    cmp ah, al
    jne wrong_dll           ; un charactere ne correspond pas on passe a la DLL suivante
 
    inc rdi                 ; on passe au charactere unicode suivant
    inc rdi
    jmp compare_dll         ; on recomence une nouvelle comparaison de chaine de charactere
 
wrong_dll:
    mov r8, [r8]            ; on passe a la _list_entry suivante ( on suit le ponteur vers Flink)
    cmp r8, r12             ; on regarde si on est revenue au debut ( le serpen qui ce mort la queu )
    jne for_each_dll
 
    xor rax, rax            ; On a pas trouver la DLL
    jmp done
 
found_dll:
    mov rbx, [r8+30h]       ; On chope l'adresse de base de la DLL, pointant vers l'entete DOS "MZ"
 
    mov r9d, [rbx+3ch]      ; On chope l'entete DOS de e_lfanew pour l'offset de l'entete "PE" 
    add r9, rbx             ; on ajoute a la base pour que r9 pointe vers _image_nt_headers64
    add r9, 88h             ; 18h pour l'entete optionel + 70h pour les repertoire de donee
                            ; r9 pointe maintenan vers l'entrer du tableau _image_data_directory[0]
                            ; qui est le repertoire d'exportation
 
    mov r13d, [r9]          ; chope l'adresse virtuel du rertoire de donee
    test r13, r13           ; si ca vaux zero, le module n'as pas de table d'exportation
    jnz has_exports
 
    xor rax, rax            ; pas d'export, la fonction ne sera pas trouver
    jmp done
 
has_exports:
    lea r8, [rbx+r13]       ; ajoute la base de la DLL pour recup la position en memoire
                            ; r8 pointe vers la structure _image_export_directory ( voir winnt.h )
 
    mov r14d, [r9+4]        ; chope la taille du repertoire d'export
    add r14, r13            ; ajoute la base rva du repertoire d'exportation
                            ; r13 et r14 contien maintenan l'intervale du repertoire d'exportation
                            ; sera utiliser plus tard pour checker si l'exportation est suivie
 
    mov ecx, [r8+18h]       ; nombre de nom
    mov r10d, [r8+20h]      ; l'adress des noms ( tableau d'RVA)
    add r10, rbx            ; ajoute la bas de la DLL
 
    dec ecx                 ; pointe vers le dernier element du tableau ( on cherche a l'envers )
for_each_func:
    lea r9, [r10 + 4*rcx]   ; chope l'index courent du tableau
 
    mov edi, [r9]           ; chope le RVA des noms
    add rdi, rbx            ; ajoute la base
    mov rsi, rdx            ; pointe vers la fonction que l'on cherche
 
compare_func:
    cmpsb
    jne wrong_func          ; le nom de la function ne corespond pas
 
    mov al, [rsi]           ; le character courent de notre fonction
    test al, al             ; check si la string est fini
    jz found_func           ; si a la fin de la chaine de charactere tout correspond, on l'a trouver!
 
    jmp compare_func        ; continue la comparaison de la chaine
 
wrong_func:
    loop for_each_func      ; esseille la fonction suivante dans le tableau
 
    xor rax, rax            ; la fonction n'est pas trouver dans la table d'exportation
    jmp done
 
found_func:                 ; ecx est un index de tableau ou on trouve le nom de la fonction
 
                            ; r8 pointe vers la structure _image_export_directory
    mov r9d, [r8+24h]       ; adress des nom originaux (rva)
    add r9, rbx             ; ajout de l'adresse base de la DLL
    mov cx, [r9+2*rcx]      ; chope la valeur original depuis le tableau de words
 
    mov r9d, [r8+1ch]       ; adresse des fonctions (rva)
    add r9, rbx             ; ajoute l'adresse base de la DLL
    mov eax, [r9+rcx*4]     ; chope l'RVA de la fonction en utilisan l'index
 
    cmp rax, r13            ; voie si la fonction RVA est dans l'intervale du repertoire d'export
    jl not_forwarded
    cmp rax, r14            ; si r13 <= func < r14 elle est alors suivie
    jae not_forwarded
 
 	; les adresse des fonctions suivie pointes vers une chaine de charactere de <Nom de la DLL>.<fonction>
    ; note: le nom de la DLL sera en majuscule
    ; extrai le nom de la DLL et ".DLL"
 
    lea rsi, [rax+rbx]      ; ajoute l'adresse base a RVA pour avoir le nom suivie
    lea rdi, [rsp+30h]      ; utilisation du registe de l'espace de stoquage de la stack pour espace de travaille
    mov r12, rdi            ; sauvegarde du pointeur du debut de chaine
 
copy_dll_name:
    movsb
    cmp byte ptr [rsi], 2eh     ; cherche '.' ( le point )
    jne copy_dll_name
 
    movsb                               ; copie aussi le point
    mov dword ptr [rdi], 004c4c44h      ; ajoute l'extention "DLL" ainsi que le charactere de fin de chaine
 
    mov rcx, r12            ; r12 pointe vers la chaine "<Nom de la DLL>.DLL" de la stack
    call r15                ; apelle de LoadLibraryA avec la DLL voulue
 
    mov rcx, r12            ; DLL voulue
    mov rdx, rsi            ; fonction voulue
    jmp start               ; recomence avec de nouveaux parametre
 
not_forwarded:
    add rax, rbx            ; ajoute l'adresse base a RVA pour recup l'adresse de la fonction
done:
    add rsp, 28h            ; on netoie la stack
    ret
 
lookup_api endp
 
end

; voila!
