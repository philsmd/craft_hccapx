# About

The goal of this project is to make it possible to generate/craft a new hashcat .hccapx file from just the few information needed (essid, AP mac, STA mac, AP nonce, STA nonce, eapol, eapol size, key version and key mic).  
The format of the .hccapx files is defined [here](https://hashcat.net/wiki/hccapx).

# Requirements

Software:  
- Perl must be installed (should work on *nix and windows with perl installed)


# Installation and First Steps

* Clone this repository:  
    git clone https://github.com/philsmd/craft_hccapx.git  
* Enter the repository root folder:  
    cd craft_hccapx
* Run it:  
    ./craft_hccapx.pl
* Check the generated file with (ocl)Hashcat:  
    ./oclHashcat64.bin -a 0 -m 2500 m02500.txt dict.txt

It is also possible to specify all the needed information directly on the command line (i.e. without entering the interactive mode).  
Each argument can be looked up in the usage/help screen:  
    ./craft_hccapx.pl --help  
  
Furthermore, each argument can be used multiple times (except --help and --outfile).  
So for instance if you specify the full set of needed arguments twice:  
    ./craft_hccapx.pl -o outfile -e "network 1" -b ... -e "network 2" -b ...  
then a .hccapx file with 2 networks inside will be created (a so called multi-hccapx file).  
  
The same can be done in interactive mode by answering the question accordingly.  

# Hacking

* More features
* CLEANUP the code, use more coding standards, everything is welcome (submit patches!)
* all bug fixes are welcome
* testing with different kinds of inputs
* solve and remove the TODOs
* and,and,and

# Credits and Contributors 
Credits go to:  
  
* philsmd, hashcat project

# License/Disclaimer

License: belongs to the PUBLIC DOMAIN, donated to hashcat, credits MUST go to hashcat and philsmd for their hard work. Thx  
  
Disclaimer: WE PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE Furthermore, NO GUARANTEES THAT IT WORKS FOR YOU AND WORKS CORRECTLY
