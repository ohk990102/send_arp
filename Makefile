CPP = 
CFLAGS = 
LDLIBS = -lpcap
TARGET = send_arp

all: $(TARGET)

debug: CFLAGS += -DDEBUG -g
debug: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CXX) -o $@ $^ $(CFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)