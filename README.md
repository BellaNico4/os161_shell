# OS161 - SHELL

**Year:** A.Y. 2019/2020
**Course:** System and Device Programming  
**Teacher:** Gianpiero Cabodi  
**Authors:**  
- Nicolò Bellarmino

---

## Project Summary

The goal of this project is to develop a basic shell environment for OS161, enabling the execution of user programs with support for concurrent process management. The shell interprets user commands and executes corresponding binaries stored in the OS161 file system, leveraging system calls such as `execv` and `dup2`.

The project includes the implementation of essential shell functionalities such as:

- Command parsing  
- Input/output redirection  
- Execution of multiple processes  

Programs are loaded into memory and run in user mode under kernel supervision.

The shell is accessed through the menu command:

```sh
p /bin/sh
