
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra

main = main.o eappacket.o md5.o
client = dcclient.o

ccnt : $(main) $(client) $(libs)
	$(CXX) $(CXXFLAGS) -o ccnt -lpcap $(main) $(client)

.PHONY:clean
clean:
	rm -f ccnt *.o

