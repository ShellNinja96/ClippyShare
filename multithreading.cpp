#include <iostream>
#include <thread>

void CountTo(unsigned int to){
    for(unsigned int i = 0; i <= to; i++) std::cout << i << std::endl;
}



int main () {

    std::thread thread_object (CountTo, 100000);
    for(unsigned int i = 100000; i > 0; i--) std::cout << i << std::endl;

    thread_object.join();
    return 0;

}
