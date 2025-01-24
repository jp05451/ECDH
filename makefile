CXX=g++
# CXXFLAGS=-std=c++17 -Wall -Wextra -Werror -pedantic -O3
CXXFLAGS=-std=c++17 -Wall -g3 -O3
LIBS=$(shell pkg-config --libs openssl)
INCLUDES=$(shell pkg-config --cflags openssl)
TARGET=main

SRC=ecdh.cpp main.cpp
OBJ=$(SRC:.cpp=.o)
OBJDIR=obj

all: $(TARGET)

$(TARGET): $(addprefix $(OBJDIR)/, $(OBJ))
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)

$(OBJDIR)/%.o: %.cpp
	@mkdir -p $(OBJDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

clean:
	rm -rf $(OBJDIR) $(TARGET)

