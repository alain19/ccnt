
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra

eap = eapclient.o eapconfig.o eapoption.o eaputility.o
main = main.o md5.o port_linux.o
client = digitalchina.o
libs = -lpcap -lboost_regex -lboost_program_options -lpthread

ccnt : $(eap) $(main) $(client)
	$(CXX) $(CXXFLAGS) -o ccnt $(eap) $(main) $(client) $(libs)

.PHONY:clean
clean:
	rm -f ccnt *.o

