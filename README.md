# Locate a DLL’s Unexported Functions

This repository contains the code and materials from my BSidesTLV 2022 talk - "Find Me If You Can! How to Locate a DLL’s Unexported Functions"

It includes the scripts I showed during the talk with their development steps for each method to locate an unexported function.

## "Find Me If You Can! How to Locate a DLL’s Unexported Functions"
### Talk Abstract

Attackers often use code from system DLLs to load libraries or run procedures. To avoid detection, they don’t use the DLL’s exported functions but rather code that is triggered deeper down the call-stack. But unlike exported functions, internal ones are harder to find in memory, so attackers need to be creative. In this talk, we will adopt the attacker mindset and locate functions in memory using IDA(Python). We will compare different approaches and try to overcome OS compatibility challenges.

### Talk Materials

* You can watch the talk [here](https://youtu.be/DAjqyCfqTF8)
* And find the slides [here](https://github.com/oryandp/LocateUnexportedFunctions/blob/main/BSidesTLV_2022/BsidesTlv%202022%20-%20Find%20Me%20If%20You%20Can!%20How%20to%20Locate%20a%20DLL%E2%80%99s%20Unexported%20Functions.pdf)

## Scripts

The scripts shows the automation process of searching the unexported function offline using IDAPython. <br />
In order to show all the steps clearly, they are divided into the different steps for each method to locate the unexported functions (total of 3 methods). <br />
The naming conventions are: <br />
[method]\_[step]\_[filename].py
