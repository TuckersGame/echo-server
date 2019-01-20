#command options
CC := gcc
RM := rm -rf
MKDIR := mkdir -p
FORMATTER := clang-format-7


#File options
SRCDIR := src
SRCS := $(shell find -L -O3 $(SRCDIR)/ -type f -name '*.c')

OBJDIR := bin
OBJS := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

DEPDIR := dependencies
DEPS := $(patsubst $(SRCDIR)/%.c,$(DEPDIR)/%.dep,$(SRCS))


#compiler configuration
WARNINGS := -Wall -Wextra -Wpedantic -Wpedantic-errors -Wmissing-include-dirs\
-Wswitch-default -Wuninitialized -Wstrict-overflow=5 -Wsuggest-override\
-Wfloat-equal -Wshadow -Wundef -Wunused-macros -Wcast-qual -Wcast-align=strict\
-Wconversion -Wzero-as-null-pointer-constant -Wformat=2 -Wuseless-cast\
-Wextra-semi -Wsign-conversion -Wlogical-op -Wmissing-declarations\
-Wredundant-decls -Winline -Winvalid-pch -Wdisabled-optimization\
-Wstrict-null-sentinel -Wsign-promo -Wbad-function-cast -Wjump-misses-init\
-Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes\
-Wnormalized=nfc -Wpadded -Wnested-externs

#build-specific compiler options
OPTIONS := -std=c18 -m64 -fPIC
LDOPTIONS := -shared -pthread
DEBUGOPTIONS := -Og -ggdb -Wno-unused
RELEASEOPTIONS := -O3 -D NDEBUG -Wunused

#libraries and included files
LIBS := $(shell pkg-config --libs-only-l openssl)
INCLUDES := -I$(SRCDIR) $(shell pkg-config --cflags-only-I openssl)

#final executable name
EXENAME := echoServer


.PHONY: debug release clean diagnose
.SECONDEXPANSION:


debug: OPTIONS := $(OPTIONS) $(DEBUGOPTIONS)
debug: $(EXENAME)
	@echo "Done compiling debug."
	@echo ""
	@echo "Debug build finished."

release: OPTIONS := $(OPTIONS) $(RELEASEOPTIONS)
release: $(EXENAME)
	@echo "Done with release."
	@echo ""
	@echo "Release build finished."


clean:
	@echo "Removing $(DEPDIR)/, $(OBJDIR)/, and $(EXENAME)"
	@$(RM) $(OBJDIR) $(DEPDIR) $(EXENAME)


$(EXENAME): $(OBJS)
	@echo "Linking..."
	@$(CC) -o $(EXENAME) $(OPTIONS) $(LDOPTIONS) $(OBJS) $(LIBS)

$(OBJS): $$(patsubst $(OBJDIR)/%.o,$(SRCDIR)/%.c,$$@) $$(patsubst $(OBJDIR)/%.o,$(DEPDIR)/%.dep,$$@) | $$(dir $$@)
	@echo "Compiling $@..."
	@$(FORMATTER) -i $(filter-out %.dep,$^)
	@$(CC) $(OPTIONS) $(INCLUDES) -c $< -o $@

$(DEPS): $$(patsubst $(DEPDIR)/%.dep,$(SRCDIR)/%.c,$$@) | $$(dir $$@)
	@set -e; $(RM) $@; \
	 $(CC) $(OPTIONS) $(INCLUDES) -MM -MT $(patsubst $(DEPDIR)/%.dep,$(OBJDIR)/%.o,$@) $< > $@.$$$$; \
	 sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	 rm -f $@.$$$$


%/:
	@$(MKDIR) $@


-include $(DEPS)