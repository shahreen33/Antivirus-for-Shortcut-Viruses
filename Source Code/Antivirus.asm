.MODEL SMALL
.STACK 100h


.DATA

DTA DB 128 DUP(0)             ;for storing the fetched file name
FILE DB 50 DUP(0);            ;file name
NEWFILE DB 128 DUP(0);        ;B+file
DELETED DW 0;                 ;count of how many files deleted
TEXT DB 700 DUP(0)            ;array of text file  
A DB 50 DUP(0)                ;directory read
B DB 50 DUP(0)                ;array to store temporary directory for comparing   
TXTFILE db 'directory.txt',00 ; stores vdrive info 
MSG_SHORTCUT DB 'ANTIVIRUS FOR SHORTCUT VIRUSES!!',0Ah, 0Dh, '$' 
MSG_SPACE DB '-----------------------', 0Ah, 0DH, '$'
MSG1 DB 'PLEASE ENTER THE DIRECTORY ADDRESS AND PRESS ENTER:',0Ah, 0Dh, '$'  
MSG2 DB 'Threats:',0Ah, 0Dh, '$' 
NT DB 'No THREATS detected!',0Ah, 0Dh, '$'
MSG3 DB 'Total Viruses deleted : ','$'
MSG4 DB 'NO SUCH DIRECTORY! ',0Ah, 0DH, '$'
ASZ DB 0                      ; size of A array
BSZ DB 0                      ; size of B array
CNT DB 0                      ; counter
MATCHED DB ?                  ; works as a boolean variable while checking if (A==B)
DIGITS DB ?   
ten DB 10 
NOT_FOUND DB 0

     
     


.CODE 

;Reading text file
readFile proc
     mov ah,3dh             
     mov al,00h
     mov dx,offset TXTFILE
     int 21h
     mov bx,ax
     mov ah,3fh
     mov cx,500
     mov dx,offset TEXT
     int 21h
     ret    
readFile endp  


;Procedure Making String B from Text string
    
MakeString PROC 
    MOV BSZ, 0 
    LEA BX, B 
    CMP BYTE PTR[DI], 0DH
    JE EXCEPTION  
    CMP BYTE PTR[DI], 0AH
    JE EXCEPTION  
    CMP BYTE PTR[DI], 0
    JE EXCEPTION  
    
    MOVE:
     
    MOV CL,BYTE PTR[DI]
    MOV BYTE PTR[BX], CL
    INC BSZ
    INC BX
    INC DI 
    
    CMP BYTE PTR[DI], 0DH
    JNE MOVE       
    INC DI
    CMP BYTE PTR[DI], 0AH
    JMP QUIT_MS 
    
    EXCEPTION:
    MOV BYTE PTR[BX], 0
    
    
    QUIT_MS:
    MOV BYTE PTR[BX], 0
    RET
MakeString ENDP  
  
;Procedure to check whether A and B is equal or not  
    
CheckString PROC
    
    LEA BX,B
    LEA SI,A 
    
   
    CMP BSZ,0
    JE DEC_NOTFOUND
     
    MOV CH, BSZ
    CMP ASZ, CH
    JG DEC1 
    
    
    
 
    
    MOV CNT, 0   
    CHCK1: 
    MOV CH, CNT
    CMP CH, ASZ
    JE CHCK2
    MOV CL,BYTE PTR[SI]
    CMP BYTE PTR[BX], CL 
    JNE CHCK_CASE
    THEN:
    INC SI
    INC BX
    INC CNT
    JMP CHCK1
    CHCK_CASE:
    ADD CL,32
    CMP BYTE PTR[BX],CL
    JE THEN
    SUB CL, 64
    CMP BYTE PTR[BX], CL
    JE THEN
    
    CHCK2:  
    MOV CH, CNT
    CMP ASZ, CH
    JE DEC2
    
    CMP ASZ, CH
    JG DEC1
    
    DEC1:
   
    MOV MATCHED, 0
    
    JMP QUIT_CS
    
    DEC2:
    MOV MATCHED, 1 
    JMP QUIT_CS
    
    DEC_NOTFOUND:
    MOV NOT_FOUND, 1
    MOV MATCHED, 0
    
    QUIT_CS:
    RET
    
CheckString ENDP
    
;Procedure for deleting the fethced shortcut file
    
DELETE PROC
        PUSH DI
        ;MAKE NEWFILE
        
        MOV SI, OFFSET B
        MOV DI, OFFSET NEWFILE 
        
        COPY1:
        
        MOVSB
        CMP BYTE PTR[SI], 0
        JE SECOND
        JMP COPY1
         
        SECOND:
        MOV SI, OFFSET FILE 
        
        COPY2:
        
        MOVSB
        CMP BYTE PTR[SI], 0
        JE DEL
        JMP COPY2
        
        
        DEL:
        MOV BYTE PTR[DI], 0
        LEA DX, NEWFILE 
        MOV AH, 41H
        INT 21H 
        
        POP DI
        
        RET
        
DELETE ENDP
        
        
; Procedure for finding shortcut file        
    
FindFile PROC
    
      PUSH DI
    
      MOV SI, OFFSET DTA+30
      MOV DI, OFFSET FILE
      
      REPEAT:
      CLD
      MOVSB
      CMP BYTE PTR[SI], 0 
      JE CHECK
      JMP REPEAT
    
      CHECK:
      
      CMP BYTE PTR[DI-1], 'K'
      JNE QUIT_FF
      
      CMP BYTE PTR[DI-2], 'N'
      JNE QUIT_FF
      
       CMP BYTE PTR[DI-3], 'L'
      JNE QUIT_FF
      
      ;PRINT 
       MOV [DI], 0DH
       MOV [DI + 1], 0AH
       MOV [DI + 2], '$'
     
       MOV AH, 9
       MOV DX, OFFSET FILE
       INT 21H
       
      ; DELETE
      
       MOV [DI], 0
       MOV [DI + 1],0
       MOV [DI + 2], 0
      
      
      CALL DELETE
      ADD DELETED, 1
      
    QUIT_FF: 
    
    POP DI
    RET
FindFile ENDP

;Procedure for searcing from an specified directory      
    
SEARCH PROC
    
   
    
    ;SET DTA
    MOV AH, 1AH
    MOV DX, OFFSET DTA
    INT 21H
    
    ; First Search
    MOV DX, OFFSET B
    MOV CX, 0
    MOV AH, 4EH
    INT 21H
    
    JC QUIT_S
    
    
    OUTER_LOOP:
     CALL FindFile
     MOV CX, 0
     MOV AH, 4FH
     INT 21H
     JC QUIT_S
     JMP OUTER_LOOP
     
     QUIT_S:
     
     RET
SEARCH ENDP

;Recursive procedure to traverse all the directories and subdirectories 
    
KillThemAll PROC
    call MakeString
    call CheckString
    
    cmp matched,0
    JNE nxt
    ret
    
    nxt:
    inc DI
    CALL SEARCH
    call KillThemAll
    
    ret
    
KillThemAll ENDP


; The Main procdedure

PRINT_COUNT PROC
    
    cmp deleted, 0
    JE NO_Threats
    LEA DX, MSG3
    mov AH, 09h
    int 21h
    
    cmp deleted, 09h
    JLE LESS
    MOV AX, deleted
    MOV DIGITS, 0
    EXTRACT_DIGITS:
    CMP AL, 0
    JE Print
    DIV ten
    MOV BL, AH
    MOV BH, 0
    PUSH BX
    ADD DIGITS, 1
    INC SI
    MOV AH, 0
    JMP EXTRACT_DIGITS
    
    Print:
    CMP DIGITS, 0
    JE QUIT_PC
    POP DX
    ADD dl, '0'
    mov AH, 02H
    int 21h
    DEC DIGITS 
    JMP Print
    
    NO_Threats:
    LEA DX, NT
    mov AH, 09h
    int 21h 
    JMP Quit_PC
    
    LESS:
    
    mov ah, 02h
    mov dX, deleted
    add dl, '0'
    int 21h 
    
    QUIT_PC:
    
    RET
    PRINT_COUNT ENDP

MACRO DISPLAY MSG 
    MOV Ah, 09h
    LEA DX, MSG
    int 21h 
endm 
MACRO NEWLINE
    ;Printing NEWLINE
    
    MOV AH, 02h
    MOV DL, 0AH
    int 21h
    
    MOV DL, 0DH
    int 21h 
endm 




HEADLINE PROC
    DISPLAY MSG_SHORTCUT
    NEWLINE
    DISPLAY MSG_SPACE 
    NEWLINE
    NEWLINE
    NEWLINE
    DISPLAY MSG1
    
ret
HEADLINE ENDP    

MAIN PROC
        
    MOV AX, @data
    MOV DS, AX
    MOV ES, AX
    Call HEADLINE
    
    LEA SI, A
    
    ;Take directory as input  
    TAKE_INPUT:
    
    MOV ah, 01h
    int 21h
    
    CMP AL, 0DH
    JE END_OF_INPUT 
    INC ASZ
    MOV BYTE PTR[SI], Al
    INC SI  
    JMP TAKE_INPUT
    
    END_OF_INPUT: 
    
    NEWLINE 
    
    ; READ FROM TEXTFILE 
    
    CALL readFile
    
     
    ;SEARCHING the directory from text array
    
    LEA DI, TEXT
    
    DO:
    CMP NOT_FOUND, 1
    JE END_DO
    
    CALL MakeString
    INC DI          
   
    CALL CheckString
    
    CMP MATCHED, 1
    JE GO 
    JMP DO
    
    END_DO: 
       DISPLAY MSG4 
       JMP EXIT
       
    
   
    GO:    
    
    NEWLINE
    DISPLAY MSG2
    
     
    CALL SEARCH
    
    CALL KillThemAll
     
     
    ;Print count
    NEWLINE
    CALL PRINT_COUNT

    EXIT:
    mov ax, 4c00h
    int 21h
    
    
MAIN ENDP
END MAIN
    
