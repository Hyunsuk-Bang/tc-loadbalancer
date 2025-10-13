sudo snap install go --classic
sudo apt-get update
sudo apt-get install clang llvm libbpf-dev -y
sudo apt install linux-headers-`uname -r`
sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
git clone https://github.com/Hyunsuk-Bang/tc-loadbalancer.git
cd tc-loadbalancer/
make run 
