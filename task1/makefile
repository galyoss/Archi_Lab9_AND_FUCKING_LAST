all: task1

task1: task1.o
	ld -m elf_i386 task1.o -o task1

task1.o: Task_1B.s
	nasm -f elf Task_1B.s -o task1.o
	
.PHONY: clean
clean:
	rm -f *.o task1


