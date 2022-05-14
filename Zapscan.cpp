#include<iostream>
#include<cstdlib>
#include<string>
#include<unistd.h>
#include<vector>
#include<list>
#include<sstream>
#include<map>
#include<utility>
#include<time.h>

#define xn std::cout<<"\n";
#define l(x) std::cout<<x<<"\n";
#define gln(x) std::getline(cin, x)

using namespace std; //namespace                       
unsigned int m_secn = 1000000; //global variable

void dspl() {
        system("clear");
        xn xn
        cout<<"                 #########################\n";
        cout<<"         #                       #\n";
        cout<<"         #  Github:    MRX-72    #\n";
        cout<<"         #  Instagram: mr.x_cpp  #\n";
        cout<<"         #                       #\n";
        cout<<"         #########################\n";
        xn xn
}

int main(int argc, char* argv[])
{
    if(argc <= 2){
        cout<<"[E] ~ Insufficient arguments provided";
    }
    else if(strcmp(argv[1],"zs")!=0){
        xn
        cerr<<"[E] ~ Invalid syntax"; xn
        cout<<"> Syntax  : zs`command`'target'"; xn
        cout<<"> Example : zs -fz 127.0.0.1"; xn
    }
    else if(strcmp(argv[1],"zs")==0 && strcmp(argv[2],"--help")==0){
        std::cout<< R"(
Syntax: zs -command- 'target'

Commands:
    [-fz] -> Fast scan

    [-bz] -> Basic port scan

    [-vz] -> Vulnerable ports scan

    [-pz] -> Specific port scan
    [Example]:  zs -pz 127.0.0.1
        )";
    }

    else if(strcmp(argv[1],"zs")==0 && strcmp(argv[2],"-fz")==0)
    {
        dspl();
        cout<<"-> S-TIME: "<<__DATE__; xn
        cout<<"-> Exact : "<<__TIME__; xn xn
        cout<<"I> _Fast-Scan_"; xn
        cout<<" ______________________\n";
        cout<<"|PORT | STATE | SERVICE|\n";
        cout<<" ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\n";
        std::ostringstream oss;
        oss<<"nmap -T4 "<< argv[3] << " | grep \"open\" ";
        system(oss.str().c_str());
        xn xn
        cout<<"[zscan][fz]> Target ["<<argv[3]<<"] scanned";
        xn xn
        cout<<"-> E-TIME: "<<__DATE__; xn
        cout<<"-> Exact : "<<__TIME__;

    }
    else if(strcmp(argv[1],"zs")==0 && strcmp(argv[2],"-bz")==0)
    {
        dspl();
        cout<<"-> S-TIME: "<<__DATE__; xn
        cout<<"-> Exact : "<<__TIME__; xn xn
        cout<<"_Basic-Scan_(Bit Slow)"; xn
        cout<<" ______________________\n";
        cout<<"|PORT | STATE | SERVICE|\n";
        cout<<" ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\n";
        std::ostringstream oss;
        oss<<"nmap -T3 "<< argv[3] << " | grep \"open\" ";
        system(oss.str().c_str());
        xn xn
        cout<<"[zscan][bz]> Target ["<<argv[3]<<"] scanned";
        xn xn
        cout<<"-> E-TIME: "<<__DATE__; xn
        cout<<"-> Exact : "<<__TIME__;

    }
    else if(strcmp(argv[1],"zs")==0 && strcmp(argv[2],"-vz")==0)
    {
        dspl();
        cout<<"-> S-TIME: "<<__DATE__; xn
        cout<<"-> Exact : "<<__TIME__; xn xn
        cout<<"_Vuln-PortScan_ (If - No ports shown => No vulnerable ports open"; xn
        cout<<" ______________________\n";
        cout<<"|PORT | STATE | SERVICE|\n";
        cout<<" ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\n";
        std::ostringstream oss;
        oss<<"nmap -T3 -p 20,21,22,139,137,445,50,443,80,8080,2325,69 "<< argv[3] << " | grep \"open\" ";
        system(oss.str().c_str());
        xn xn
        cout<<"[zscan][vz]> Target ["<<argv[3]<<"] scanned";
        xn xn
        cout<<"-> E-TIME: "<<__DATE__; xn
        cout<<"-> Exact : "<<__TIME__;

    }
    else if(strcmp(argv[1],"zs")==0 && strcmp(argv[2],"-pz")==0)
    {
        dspl();
        int x, y;
        cout<<"[Z-S]> First port: ";
        cin>> x;  xn
        cout<<"[Z-S]> Last port: ";
        cin>> y; xn
        cout<<"I> Scan Range ["<<x<<" - "<<y<<"]";
        xn xn
        cout<<"-> S-TIME: "<<__DATE__; xn
        cout<<"-> Exact : "<<__TIME__; xn xn
        cout<<" _____________________\n";
        cout<<"|PORT | STATE | SERVICE|\n";
        cout<<" ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\n";
        std::ostringstream oss;
        oss<<"nmap -T4 -p "<<x<<"-"<<y<<" "<< argv[3] << " | grep \"open\" ";
        system(oss.str().c_str());
        xn xn
        cout<<"[zscan][pz]> Target ["<<argv[3]<<"] scanned";
        xn xn
        cout<<"-> E-TIME: "<<__DATE__; xn
        cout<<"-> Exact : "<<__TIME__;

    }
    xn xn return 0;
}
