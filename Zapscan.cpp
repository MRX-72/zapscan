#include<iostream>
#include<ctime>
#include<sstream>
#include<chrono>
#include<string>
#include<time.h>

#define xn std::cout<<"\n";

using namespace std; //namespace

void dspl() {
        system("clear");
        xn xn
        cout<<"         #########################\n";
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

    [-Gz] -> Ping the Target
    [O% packet loss  => Target is up]

    [-Sz] -> Specific port scan
    [syntax: zap zs -Sz (portnumber) $Target]
        )";
    }

    else if(strcmp(argv[1],"zs")==0 && strcmp(argv[2],"-fz")==0)
    {
        dspl();
        cout<<"-> S-Date: "<<__DATE__; xn
        cout<<"-> Exact : "<<__TIME__; xn xn
        cout<<"I> _Fast-Scan_"; xn
        cout<<" ______________________\n";
        cout<<"|PORT | STATE | SERVICE|\n";
        cout<<" ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\n";
        std::ostringstream oss;
        oss<<"nmap -F "<< argv[3] << " | grep \"open \\| filtered \" ";
        std::chrono::time_point<std::chrono::system_clock> start,end;
        start = std::chrono::system_clock::now();
        system(oss.str().c_str());
        xn xn
        cout<<"[zscan][fz]> Target ["<<argv[3]<<"] scanned";
        xn xn
        end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        std::time_t end_time = std::chrono::system_clock::to_time_t(end);
        cout<<"-> E-Date: "<<std::ctime(&end_time); xn
        cout<<"-> T-Tkn : "<<elapsed_seconds.count()<<" seconds";

    }
    else if(strcmp(argv[1],"zs")==0 && strcmp(argv[2],"-bz")==0)
    {
        dspl();
        cout<<"-> S-Date: "<<__DATE__; xn
        cout<<"-> Exact : "<<__TIME__; xn xn
        cout<<"_Basic-Scan_(Bit Slow)"; xn
        cout<<" ______________________\n";
        cout<<"|PORT | STATE | SERVICE|\n";
        cout<<" ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\n";
        std::chrono::time_point<std::chrono::system_clock> start,end;
        start = std::chrono::system_clock::now();
        std::ostringstream oss;
        oss<<"nmap "<< argv[3] << " | grep \"open \\| filtered \" ";
        system(oss.str().c_str());
        xn xn
        cout<<"[zscan][bz]> Target ["<<argv[3]<<"] scanned";
        xn xn
        end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        std::time_t end_time = std::chrono::system_clock::to_time_t(end);
        cout<<"-> E-Date: "<<std::ctime(&end_time); xn
        cout<<"-> T-Tkn : "<<elapsed_seconds.count()<<" seconds";
    }
    else if(strcmp(argv[1],"zs")==0 && strcmp(argv[2],"-vz")==0)
    {
        dspl();
        cout<<"-> S-Date: "<<__DATE__; xn
        cout<<"-> Exact : "<<__TIME__; xn xn
        cout<<"_Vuln-PortScan_ (If - No ports shown => No vulnerable ports open"; xn
        cout<<" ______________________\n";
        cout<<"|PORT | STATE | SERVICE|\n";
        cout<<" ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\n";
        std::ostringstream oss;
        oss<<"nmap -p 20,21,22,139,137,445,50,443,80,8080,2325,69 "<< argv[3] << " | grep \"open \\| closed \\| filtered \" ";
        std::chrono::time_point<std::chrono::system_clock> start,end;
        start = std::chrono::system_clock::now();
        system(oss.str().c_str());
        xn xn
        cout<<"[zscan][vz]> Target ["<<argv[3]<<"] scanned";
        xn xn
        end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        std::time_t end_time = std::chrono::system_clock::to_time_t(end);
        cout<<"-> E-Date: "<<std::ctime(&end_time); xn
        cout<<"-> T-Tkn : "<<elapsed_seconds.count()<<" seconds";

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
        cout<<"-> S-Date: "<<__DATE__; xn
        cout<<"-> Exact : "<<__TIME__; xn xn
        cout<<" _____________________\n";
        cout<<"|PORT | STATE | SERVICE|\n";
        cout<<" ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\n";
        std::ostringstream oss;
        oss<<"nmap -F -p "<<x<<"-"<<y<<" "<< argv[3] << " | grep \"open \\| filtered \" ";
        std::chrono::time_point<std::chrono::system_clock> start,end;
        start = std::chrono::system_clock::now();
        system(oss.str().c_str());
        xn xn
        cout<<"[zscan][pz]> Target ["<<argv[3]<<"] scanned";
        xn xn
        end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        std::time_t end_time = std::chrono::system_clock::to_time_t(end);
        cout<<"-> E-Date: "<<std::ctime(&end_time); xn
        cout<<"-> T-Tkn : "<<elapsed_seconds.count()<<" seconds";

    }
    else if(strcmp(argv[1],"zs")==0 && strcmp(argv[2],"-Gz")==0)
    {
        dspl();
        cout<<"-> S-Date: "<<__DATE__; xn
        cout<<"-> Exact : "<<__TIME__; xn xn
        cout<<"I> _Target-Ping_"; xn
        xn
        std::ostringstream oss;
        cout<<"(I)> [Ping] ~ "; xn xn
        oss<<"ping -c1 -s1 "<< argv[3]<<" | grep \"1 packet\" ";
        std::chrono::time_point<std::chrono::system_clock> start,end;
        start = std::chrono::system_clock::now();
        system(oss.str().c_str());
        xn
        cout<<"[zscan][Gz]> Target ["<<argv[3]<<"] RSLT";
        xn xn
        end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        std::time_t end_time = std::chrono::system_clock::to_time_t(end);
        cout<<"-> E-Date: "<<std::ctime(&end_time); xn
        cout<<"-> T-Tkn : "<<elapsed_seconds.count()<<" seconds";

    }

   else if(strcmp(argv[1],"zs")==0 && strcmp(argv[2],"-Sz")==0)
    {
        dspl();
        std::ostringstream oss;
        cout<<"-> S-Date: "<<__DATE__; xn
        cout<<"-> Exact : "<<__TIME__; xn xn
        cout<<" _____________________\n";
        cout<<"|PORT | STATE | SERVICE|\n";
        cout<<" ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\n";
        oss<<"nmap -p "<< argv[3]<<" "<<argv[4]<<" | grep \"open \\| closed \\| filtered \" ";
        std::chrono::time_point<std::chrono::system_clock> start,end;
        start = std::chrono::system_clock::now();
        system(oss.str().c_str());
        xn
        cout<<"[zscan][Sz]> Target ["<<argv[3]<<"] RSLT";
        xn xn
        end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        std::time_t end_time = std::chrono::system_clock::to_time_t(end);
        cout<<"-> E-Date: "<<std::ctime(&end_time); xn
        cout<<"-> T-Tkn : "<<elapsed_seconds.count()<<" seconds";

    }
    xn xn return 0;
}
