# Zapscan
Portscannner made with C++ 

# Author: MrX

> The tool Zapscan, is made with the combination 
> of Nmap and C++, it gives user friendly output 
> and is simple to use.

# Installation and Setup:

``` mkdir Zap-Scan ```
> 
``` cd Zap-Scan ``` 
> 
```https://github.com/MRX-72/zapscan ```
> 
``` cd zapscan ```
> 
``` bash req.sh ```
> 
# Compiling 
 
``` g++ Zapscan.cpp -o zap ```

# Using the tool

``` ./zap zs --help ```
> 

Trial command : 
> 
``` ./zap zs -fz scanme.nmap.org```

# Output of the Command :
```
         #########################
         #                       #
         #  Github:    MRX-72    #
         #  Instagram: mr.x_cpp  #
         #                       #
         #########################


-> S-Date: May 16 2022
-> T-Tkn : 16:14:57

I> _Fast-Scan_
 ______________________
|PORT | STATE | SERVICE|
 ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
9929/tcp  open  nping-echo
31337/tcp open  Elite


[zscan][fz]> Target [scanme.nmap.org] scanned

-> E-Date: Mon May 16 16:31:47 2022

-> T-Tkn : 7.02865 seconds

```

# Note 
>
> Scanning speed might vary depending on the internet connection
