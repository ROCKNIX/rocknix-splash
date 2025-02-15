# Source files to be compiled
SRCS=main.c fbsplash.c svg_parser.c svg_renderer.c dt_rotation.c

# Generate object file names from source files by replacing .c with .o
OBJS=$(SRCS:.c=.o)

# Name of the final executable
TARGET=rocknix-splash

# Installation directory
PREFIX=/usr
BINDIR=$(PREFIX)/bin

# Declare phony targets that don't represent actual files
.PHONY: all clean install

# Default target that builds everything
all: $(TARGET)

# Link object files to create the final executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Generic rule for compiling .c files into .o files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Install the executable
install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)

# Clean target removes all generated files
clean:
	rm -f $(OBJS) $(TARGET)
