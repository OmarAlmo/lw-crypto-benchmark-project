/* Reference implementation of ACE32 AE1024  (2, 16)
 Written by:
 Yunjie Yi <yunjie.yi@uwaterloo.ca>
 */

        PUBLIC  __iar_program_start
        PUBLIC  __vector_table

        SECTION .text:CODE:REORDER(1)
        
        ;; Keep vector table even if it's not referenced
        REQUIRE __vector_table
        
        THUMB
        
__iar_program_start

;;;BEGIN
        PUSH {R10, R11}
;;;save rc               
        LDR R11,=0x20000000
        
        LDR R10, =0x07
        STR R10, [R11, #0]
        LDR R10, =0x53
        STR R10, [R11, #4]
        LDR R10, =0x43
        STR R10, [R11, #8]
        LDR R10, =0x0a
        STR R10, [R11, #12]
        LDR R10, =0x5d
        STR R10, [R11, #16]
        LDR R10, =0xe4
        STR R10, [R11, #20]
        LDR R10, =0x9b
        STR R10, [R11, #24]
        LDR R10, =0x49
        STR R10, [R11, #28]
        LDR R10, =0x5e
        STR R10, [R11, #32]
        LDR R10, =0xe0
        STR R10, [R11, #36]
        LDR R10, =0x7f
        STR R10, [R11, #40]
        LDR R10, =0xcc
        STR R10, [R11, #44]
        LDR R10, =0xd1
        STR R10, [R11, #48]
        LDR R10, =0xbe
        STR R10, [R11, #52]
        LDR R10, =0x32
        STR R10, [R11, #56]
        LDR R10, =0x1a
        STR R10, [R11, #60]
        LDR R10, =0x1d
        STR R10, [R11, #64]
        LDR R10, =0x4e
        STR R10, [R11, #68]
        LDR R10, =0x22
        STR R10, [R11, #72]
        LDR R10, =0x28
        STR R10, [R11, #76]
        LDR R10, =0x75
        STR R10, [R11, #80]
        LDR R10, =0xf7
        STR R10, [R11, #84]
        LDR R10, =0x6c
        STR R10, [R11, #88]
        LDR R10, =0x25
        STR R10, [R11, #92]
        LDR R10, =0x62
        STR R10, [R11, #96]
        LDR R10, =0x82
        STR R10, [R11, #100]
        LDR R10, =0xfd
        STR R10, [R11, #104]
        LDR R10, =0x96
        STR R10, [R11, #108]
        LDR R10, =0x47
        STR R10, [R11, #112]
        LDR R10, =0xf9
        STR R10, [R11, #116]
        LDR R10, =0x71
        STR R10, [R11, #120]
        LDR R10, =0x6b
        STR R10, [R11, #124]
        LDR R10, =0x76
        STR R10, [R11, #128]
        LDR R10, =0xaa
        STR R10, [R11, #132]
        LDR R10, =0x88
        STR R10, [R11, #136]
        LDR R10, =0xa0
        STR R10, [R11, #140]

        LDR R10, =0x2b
        STR R10, [R11, #144]
        LDR R10, =0xdc
        STR R10, [R11, #148]
        LDR R10, =0xb0
        STR R10, [R11, #152]
        LDR R10, =0xe9
        STR R10, [R11, #156]
        LDR R10, =0x8b
        STR R10, [R11, #160]
        LDR R10, =0x09
        STR R10, [R11, #164]
        LDR R10, =0xcf
        STR R10, [R11, #168]
        LDR R10, =0x59
        STR R10, [R11, #172]
        LDR R10, =0x1e
        STR R10, [R11, #176]
        LDR R10, =0xb7
        STR R10, [R11, #180]        
        LDR R10, =0xc6
        STR R10, [R11, #184]
        LDR R10, =0xad
        STR R10, [R11, #188]


;; finished store INDICATOR for memory jump

        LDR R11,=0x20000100

        LDR R10, =0x50
        STR R10, [R11, #0]
        LDR R10, =0x28
        STR R10, [R11, #4]
        LDR R10, =0x14
        STR R10, [R11, #8]
        LDR R10, =0x5C
        STR R10, [R11, #12]
        LDR R10, =0xAE
        STR R10, [R11, #16]
        LDR R10, =0x57
        STR R10, [R11, #20]
        LDR R10, =0x91
        STR R10, [R11, #24]
        LDR R10, =0x48
        STR R10, [R11, #28]
        LDR R10, =0x24
        STR R10, [R11, #32]
        LDR R10, =0x8D
        STR R10, [R11, #36]
        LDR R10, =0xC6
        STR R10, [R11, #40]
        LDR R10, =0x63
        STR R10, [R11, #44]
        LDR R10, =0x53
        STR R10, [R11, #48]
        LDR R10, =0xA9
        STR R10, [R11, #52]
        LDR R10, =0x54
        STR R10, [R11, #56]
        LDR R10, =0x60
        STR R10, [R11, #60]
        LDR R10, =0x30
        STR R10, [R11, #64]
        LDR R10, =0x18
        STR R10, [R11, #68]
        LDR R10, =0x68
        STR R10, [R11, #72]
        LDR R10, =0x34
        STR R10, [R11, #76]
        LDR R10, =0x9A
        STR R10, [R11, #80]
        LDR R10, =0xE1
        STR R10, [R11, #84]
        LDR R10, =0x70
        STR R10, [R11, #88]
        LDR R10, =0x38
        STR R10, [R11, #92]
        LDR R10, =0xF6
        STR R10, [R11, #96]
        LDR R10, =0x7B
        STR R10, [R11, #100]
        LDR R10, =0xBD
        STR R10, [R11, #104]
        LDR R10, =0x9D
        STR R10, [R11, #108]
        LDR R10, =0xCE
        STR R10, [R11, #112]
        LDR R10, =0x67
        STR R10, [R11, #116]
        LDR R10, =0x40
        STR R10, [R11, #120]
        LDR R10, =0x20
        STR R10, [R11, #124]
        LDR R10, =0x10
        STR R10, [R11, #128]
        LDR R10, =0x4F
        STR R10, [R11, #132]
        LDR R10, =0x27
        STR R10, [R11, #136]
        LDR R10, =0x13
        STR R10, [R11, #140]

        LDR R10, =0xBE
        STR R10, [R11, #144]
        LDR R10, =0x5F
        STR R10, [R11, #148]
        LDR R10, =0x2F
        STR R10, [R11, #152]
        LDR R10, =0x5B
        STR R10, [R11, #156]
        LDR R10, =0xAD
        STR R10, [R11, #160]
        LDR R10, =0xD6
        STR R10, [R11, #164]
        LDR R10, =0xE9
        STR R10, [R11, #168]
        LDR R10, =0x74
        STR R10, [R11, #172]
        LDR R10, =0xBA
        STR R10, [R11, #176]
        LDR R10, =0x7F
        STR R10, [R11, #180]        
        LDR R10, =0x3F
        STR R10, [R11, #184]
        LDR R10, =0x1F
        STR R10, [R11, #188]     

;; finished the store of t and SC



;;begin load value to the designated
        LDR R11,=0x20000200
        
        LDR R10, =0x00000000
        STR R10, [R11, #0]
        LDR R10, =0x00000000
        STR R10, [R11, #4]
        
        LDR R10, =0x00000000
        STR R10, [R11, #8]
        LDR R10, =0x00000000
        STR R10, [R11, #12]
        
        LDR R10, =0x00000000
        STR R10, [R11, #16]
        LDR R10, =0x00000000
        STR R10, [R11, #20]
        
        LDR R10, =0x00000000
        STR R10, [R11, #24]
        LDR R10, =0x00000000
        STR R10, [R11, #28]
        
        LDR R10, =0x00000000
        STR R10, [R11, #32]
        LDR R10, =0x00000000
        STR R10, [R11, #36]
                             
        POP {R10, R11}
 ;;finish load value to the designated       

        BL FFUNAE

main    B       main ;; Program finished, LOOP

;;this is the mode 
FFUNAE
        PUSH {LR}
        
        BL FFUN3        
        BL FFUNKEY
        BL FFUNAD
        BL FFUNM
        BL FFUNKEY

        
        POP {LR}
        BX lr
        
FFUNKEY
        PUSH {LR}
        
        LDR R11,=0x20000200        
        LDR R3, [R11, #36]      ;;A[7]-A[4]
        LDR R2, [R11, #20]         ;;C[7]-C[4]       
        LDR R1, [R11, #0]         ;;E[0]
        EOR R3, R3, #0x00000000
        EOR R2, R2, #0x00000000
        EOR R1, R1, #0x00000000       
        STR R3, [R11, #36]      ;;A[7]-A[4]
        STR R2, [R11, #20]         ;;C[7]-C[4]
        STR R1, [R11, #0]         ;;E[0]

        BL FFUN3
        
        LDR R11,=0x20000200        
        LDR R3, [R11, #36]      ;;A[7]-A[4]
        LDR R2, [R11, #20]         ;;C[7]-C[4]       
        LDR R1, [R11, #0]         ;;E[0]
        EOR R3, R3, #0x00000000
        EOR R2, R2, #0x00000000
        EOR R1, R1, #0x00000000     
        STR R3, [R11, #36]      ;;A[7]-A[4]
        STR R2, [R11, #20]         ;;C[7]-C[4]       
        STR R1, [R11, #0]         ;;E[0]

        BL FFUN3

        POP {LR}
        BX lr
        
;;this is the AD absorption part in the mode
FFUNAD
        PUSH {LR}

        LDR R5,=0
        LDR R6,=2   ;; S = 2
WHILE9  CMP R5,R6
        BGE NEXT9
        
        LDR R11,=0x20000200        
        LDR R3, [R11, #36]      ;;A[7]-A[4]
        LDR R2, [R11, #20]         ;;C[7]-C[4]       
        LDR R1, [R11, #0]         ;;E[0]
        EOR R3, R3, #0x00000000
        EOR R2, R2, #0x00000000
        EOR R1, R1, #0x00000001     
        STR R3, [R11, #36]      ;;A[7]-A[4]
        STR R2, [R11, #20]         ;;C[7]-C[4]       
        STR R1, [R11, #0]         ;;E[0]

        BL FFUN3
        
        ADD R5, R5, #1
        B WHILE9
NEXT9

        POP {LR}
        BX lr
        
        
;;this is the message absorption part in the mode       
FFUNM
        PUSH {LR}

        LDR R5,=0
        LDR R6,=16   ;; S = 16
WHILE8  CMP R5,R6
        BGE NEXT8
       
        
        LDR R11,=0x20000200        
        LDR R3, [R11, #36]      ;;A[7]-A[4]
        LDR R2, [R11, #20]         ;;C[7]-C[4]       
        LDR R1, [R11, #0]         ;;E[0]
        EOR R3, R3, #0x00000000
        EOR R2, R2, #0x00000000
        EOR R1, R1, #0x00000002     
        STR R3, [R11, #36]      ;;A[7]-A[4]
        STR R2, [R11, #20]         ;;C[7]-C[4]       
        STR R1, [R11, #0]         ;;E[0]

        BL FFUN3

        ADD R5, R5, #1
        B WHILE8
NEXT8 

        POP {LR}
        BX lr
        
        
;;this is permutation box         
FFUN3   ;;LOOP the sliscp-light ;;pass [R7, R6], [R5, R4], [R3, R2], [R1, R0], and data stored at 20000000-200000xx and 20000100-200001xx
        PUSH {R0, R4, R5, R6, R7, R8, R9, R10, R11, R12, LR}
;record the offset whic is used in FFUN2 and FFUN3
        LDR R11,=0x20000000
        LDR R10, =0x00
        STR R10, [R11, #200]
;; store INDICATOR for memory jump
        LDR R10, =0x00000000 ;;initial value is 0
        STR R10, [R11, #204] 
;;finished init
        LDR R10,=0
        LDR R11,=16   ;; S = 16
WHILE2  CMP R10,R11
        BGE NEXT2
        BL FFUN2
        ADD R10, R10, #1
        B WHILE2
NEXT2   
        POP {R0, R4, R5, R6, R7, R8, R9, R10, R11, R12, LR}
        BX lr
        
    
        
;;this is permutation round       
FFUN2   ;;pass 000(#0-188, #200, #204), 100(#0-188), 200(#0-36), 300(#0-36) where 100 means 0x20000100, similar to others
        PUSH {R10, R11, LR}

        LDR R11,=0x20000000
        LDR R10, [R11, #200] ;;load the index counter, do not alter r10 in any calculation
        LDR R12, [R11, R10] ;GET 1st t******

        LDR R0, [R11, #204]; load indicator to R10
        CMP R0, #0x00000000
        BGT EvenOperation
        
;; Odd operation branch:       
        LDR R11,=0x20000200
        
        LDR R5,[R11, #36] ;load A Data__________
        LDR R4,[R11, #32]
        BL FFUN ;;finish the leftmost h on the left side
        LDR R11,=0x20000300
        STR R5, [R11, #20]  ;;store to the temp location
        STR R4, [R11, #16]  ;;finish A Data__________



        LDR R11,=0x20000200  
        LDR R7,[R11, #28]  ;load B and C data_________
        LDR R6,[R11, #24]
        LDR R5,[R11, #20]
        LDR R4,[R11, #16]

        LDR R11,=0x20000100
        LDR R9, [R11, R10] ;GET 1st sc ******    
        
        ADD R10, R10, #4 ;; index change point!!!!!!!!!!!!!!    
   
        LDR R11,=0x20000000
        LDR R12, [R11, R10] ;GET 2nd t ******
;;******special operation done here to save cycles
        LDR R0, =0x00000001 ;; set the index to be 1 for next round
        STR R0, [R11, #204]
;;******End special operation done here to save cycles

        BL FFUN ;;finish the left 2nd h on the left side

        EOR R7, R7, #0xFFFFFFFF
        ORR R9, R9, #0xFFFFFF00
        EOR R6, R6, R9 ;;R7 and R6 finished EOR with 1st SC

        EOR R7, R7, R5
        EOR R6, R6, R4

        LDR R11,=0x20000300
        STR R7, [R11, #4]  ;;store to the temp location
        STR R6, [R11, #0]
        STR R5, [R11, #28]
        STR R4, [R11, #24] ;; ;FINISH THE B AND C Data____________

        LDR R11,=0x20000200
        LDR R7,[R11, #12] ;load D and E data_________
        LDR R6,[R11, #8]
        LDR R5,[R11, #4]
        LDR R4,[R11, #0]
        
        LDR R11,=0x20000100
        LDR R9, [R11, R10] ;Get 2nd sc ******

        ADD R10, R10, #4 ;; index change point!!!!!!!!!!!!!!

        LDR R11,=0x20000000
        LDR R12, [R11, R10] ;GET 3rd t ******


        LDR R11,=0x20000100
        LDR R8, [R11, R10] ;GET 3rd sc ******         
        
        BL FFUN ;;right most E;??????????????????

        EOR R7, R7, #0xFFFFFFFF
        ORR R9, R9, #0xFFFFFF00
        EOR R6, R6, R9 ;;R7 and R6 finished EOR with 1st SC       

        EOR R7, R7, R5
        EOR R6, R6, R4
        
        EOR R5, R5, #0xFFFFFFFF
        ORR R8, R8, #0xFFFFFF00
        EOR R4, R4, R8 ;;R7 and R6 finished EOR with 1st SC          
        
        LDR R11,=0x20000300
        STR R7, [R11, #36]  ;;store to the temp location
        STR R6, [R11, #32]
        LDR R7, [R11, #20]  ;;store to the temp location
        LDR R6, [R11, #16]
        EOR R5, R5, R7
        EOR R4, R4, R6        
        STR R5, [R11, #12]
        STR R4, [R11, #8] ;; FINISH THE D AND E Data____________
        
        B OperationFinish
;;End odd operation branch.

;; For even operation branch:    
EvenOperation
        LDR R11,=0x20000300
        LDR R5,[R11, #36] ;load A Data__________
        LDR R4,[R11, #32]
        BL FFUN ;;finish the leftmost h on the left side
        LDR R11,=0x20000200
        STR R5, [R11, #20]  ;;store to the temp location
        STR R4, [R11, #16]  ;;finish A Data__________



        LDR R11,=0x20000300  
        LDR R7,[R11, #28]  ;load B and C data_________
        LDR R6,[R11, #24]
        LDR R5,[R11, #20]
        LDR R4,[R11, #16]

        LDR R11,=0x20000100
        LDR R9, [R11, R10] ;GET 1st sc ******    
        
        ADD R10, R10, #4 ;; index change point!!!!!!!!!!!!!!    
   
        LDR R11,=0x20000000
        LDR R12, [R11, R10] ;GET 2nd t ******
;;******special operation done here to save cycles
        LDR R0, =0x00000000 ;; set the index to be 1 for next round
        STR R0, [R11, #204]
;;******End special operation done here to save cycles

        BL FFUN ;;finish the left 2nd h on the left side

        EOR R7, R7, #0xFFFFFFFF
        ORR R9, R9, #0xFFFFFF00
        EOR R6, R6, R9 ;;R7 and R6 finished EOR with 1st SC

        EOR R7, R7, R5
        EOR R6, R6, R4

        LDR R11,=0x20000200
        STR R7, [R11, #4]  ;;store to the temp location
        STR R6, [R11, #0]
        STR R5, [R11, #28]
        STR R4, [R11, #24] ;; ;FINISH THE B AND C Data____________

        LDR R11,=0x20000300
        LDR R7,[R11, #12] ;load D and E data_________
        LDR R6,[R11, #8]
        LDR R5,[R11, #4]
        LDR R4,[R11, #0]
        
        LDR R11,=0x20000100
        LDR R9, [R11, R10] ;Get 2nd sc ******

        ADD R10, R10, #4 ;; index change point!!!!!!!!!!!!!!

        LDR R11,=0x20000000
        LDR R12, [R11, R10] ;GET 3rd t ******


        LDR R11,=0x20000100
        LDR R8, [R11, R10] ;GET 3rd sc ******         
        
        BL FFUN ;;right most E

        EOR R7, R7, #0xFFFFFFFF
        ORR R9, R9, #0xFFFFFF00
        EOR R6, R6, R9 ;;R7 and R6 finished EOR with 1st SC       

        EOR R7, R7, R5
        EOR R6, R6, R4
        
        EOR R5, R5, #0xFFFFFFFF
        ORR R8, R8, #0xFFFFFF00
        EOR R4, R4, R8 ;;R7 and R6 finished EOR with 1st SC          
        
        LDR R11,=0x20000200
        STR R7, [R11, #36]  ;;store to the temp location
        STR R6, [R11, #32]
        LDR R7, [R11, #20]  ;;store to the temp location
        LDR R6, [R11, #16]
        EOR R5, R5, R7
        EOR R4, R4, R6        
        STR R5, [R11, #12]
        STR R4, [R11, #8] ;; FINISH THE D AND E Data____________        

OperationFinish
        ADD R10, R10, #4 ;; index change point!!!!!!!!!!!!!!
        LDR R11,=0x20000000
        STR R10, [R11, #200]
        POP {R10, R11, LR}     
        BX lr
        
        
;;this is Simeck box
FFUN    ;;Make Round for the siemckR, pass R5, R4, R12, where R12 is the "rc" 
        PUSH {R8, R9, R10, R11, LR}
        LDR R10,=0
        LDR R11,=8   ;; u = 8
WHILE   CMP R10,R11
        BGE NEXT1
        BL SimeckR
        ADD R10, R10, #1
        B WHILE
NEXT1   
        POP {R8, R9, R10, R11, LR}
        BX lr
;;funn end

;; this is Simeck round
SimeckR     ;;PASS R5, R4, R12 in, where R12 is the "rc"
        PUSH {LR}
        ROR R8, R5, #27  ;;=32-5 a
        AND R8, R8, R5  ;;32-0
        ROR R9, R5, #31 ;;=32-1
        EOR R8, R8, R9 ;;pass the value from left side to right of the figure 1
        EOR R8, R8, R4 ;;wait to EOR rc
        MOV R4, R5
        
        ;LDR R9, =0x1  ;;redefine R9, try to get 111..11x where x is the last bit of R12
        ;AND R9, R9, R12 ; Then R9 = 0000...000X in bit
        ;ORR R9, R9, #0xFFFFFFFE ;;Then R9 = 111...11X in bit
        ORR R9, R12, #0xFFFFFFFE ;;Correct?
        EOR R5, R8, R9 ;finish the one round
        LSR R12, r12, #1
        POP {LR}       
        BX lr                ; Return from subroutine


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; Forward declaration of sections.
        SECTION CSTACK:DATA:NOROOT(3)
        SECTION .intvec:CODE:NOROOT(2)
        
        DATA

__vector_table
        DCD     sfe(CSTACK)
        DCD     __iar_program_start

        DCD     NMI_Handler
        DCD     HardFault_Handler
        DCD     MemManage_Handler
        DCD     BusFault_Handler
        DCD     UsageFault_Handler
        DCD     0
        DCD     0
        DCD     0
        DCD     0
        DCD     SVC_Handler
        DCD     DebugMon_Handler
        DCD     0
        DCD     PendSV_Handler
        DCD     SysTick_Handler

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; Default interrupt handlers.
;;

        PUBWEAK NMI_Handler
        PUBWEAK HardFault_Handler
        PUBWEAK MemManage_Handler
        PUBWEAK BusFault_Handler
        PUBWEAK UsageFault_Handler
        PUBWEAK SVC_Handler
        PUBWEAK DebugMon_Handler
        PUBWEAK PendSV_Handler
        PUBWEAK SysTick_Handler

        SECTION .text:CODE:REORDER:NOROOT(1)
        THUMB

NMI_Handler
HardFault_Handler
MemManage_Handler
BusFault_Handler
UsageFault_Handler
SVC_Handler
DebugMon_Handler
PendSV_Handler
SysTick_Handler
Default_Handler
__default_handler
        CALL_GRAPH_ROOT __default_handler, "interrupt"
        NOCALL __default_handler
        B __default_handler

        END
