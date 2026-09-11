CXX = g++
CXXFLAGS = -O2 -std=c++17 -Wall
LDLIBS = -lpcap

raw_capture: raw_capture.cpp
	$(CXX) $(CXXFLAGS) raw_capture.cpp $(LDLIBS) -o raw_capture

clean:
	rm -f raw_capture
